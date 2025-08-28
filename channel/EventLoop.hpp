
#ifndef HYSBURG_EVENT_LOOP_H
#define HYSBURG_EVENT_LOOP_H

#include <cstdint>
#include <map>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <utility>
#include <thread>
#include <functional>

#include <uv.h>

namespace hysburg
{

class EventLoop;
class EventLoopGroup;

using EventLoopPtr = std::shared_ptr<EventLoop>;
using EventLoopGroupPtr = std::shared_ptr<EventLoopGroup>;

class EventLoop {
    struct PostReq {
        uint64_t id = 0;
        long delay = 0;
        std::function<void()> rcb;
        uv_timer_t timer {};
        EventLoop *eventLoop = nullptr;
    };
    using PostReqPtr = std::unique_ptr<PostReq>;

    uint64_t mLooperThreadId = 0;
    uv_loop_t mLooper {};

    std::atomic<uint64_t> mTimerId { 1 };
    std::map<uint64_t, PostReqPtr> mPostReq;

    std::mutex mMutex;
    uv_async_t mAsync {};
    volatile bool mAsyncReady = false;
    std::map<uint64_t, PostReqPtr> mOuterPostReq;

    std::weak_ptr<EventLoopGroup> mParent;


    void flushOuterReq() noexcept {
        std::map<uint64_t, PostReqPtr> cpy;
        {
            std::unique_lock lockGuard(mMutex);
            cpy.swap(mOuterPostReq);
        }
        for (auto &it : cpy) {
            insertInnerReq(std::move(it.second));
        }
    }

    void insertInnerReq(PostReqPtr pReq) noexcept {
        auto *req = pReq.get();
        mPostReq[req->id] = std::move(pReq);
        uv_timer_init(&mLooper, &req->timer);
        req->timer.data = req;
        uv_timer_start(
                &req->timer,
                [](uv_timer_t *tm) {
                    auto tmp = static_cast<PostReq*>(tm->data);
                    auto req = std::move(tmp->eventLoop->mPostReq[tmp->id]);
                    // 先从 map 中移除自己，防止回调 cb 的时候辗转调用到 cancel
                    req->eventLoop->mPostReq.erase(req->id);
                    if (req->rcb) { req->rcb(); }
                },
                req->delay,
                0
        );
    }

    void cancelOuterReq(uint64_t id) noexcept {
        std::unique_lock lockGuard(mMutex);
        auto it = mOuterPostReq.find(id);
        if (it != mOuterPostReq.end()) {
            mOuterPostReq.erase(it);
        }
    }

    void cancelInnerReq(uint64_t id) noexcept {
        auto it = mPostReq.find(id);
        if (it != mPostReq.end()) {
            auto req = std::move(it->second);
            uv_timer_stop(&req->timer);
            mPostReq.erase(it);
        }
    }

public:
    explicit EventLoop() noexcept = default;
    NO_COPY(EventLoop)

    void loop() {
        std::unique_lock lockGuard(mMutex);
        CHECK(!mLooperThreadId, "another looper !")

        uv_loop_init(&mLooper);
        uv_async_init(&mLooper, &mAsync, [](uv_async_t *async) {
            auto self = static_cast<EventLoop*>(async->data);
            self->flushOuterReq();
        });
        mAsync.data = this;
        mAsyncReady = true;
        mLooperThreadId = Log::threadId();
        lockGuard.unlock();

        // 正在队列中的临时事件需要插入进去
        flushOuterReq();

        // 开始循环
        uv_run(&mLooper, UV_RUN_DEFAULT);

        // 已经退出，销毁掉资源
        uv_loop_close(&mLooper);
    }

    uint64_t post(std::function<void()> cb) noexcept {
        return post(0, std::move(cb));
    }

    uint64_t post(long ms, std::function<void()> cb) noexcept {
        auto id = mTimerId.fetch_add(1, std::memory_order_relaxed);
        auto req = std::make_unique<PostReq>();
        req->delay = ms;
        req->rcb = std::move(cb);
        req->eventLoop = this;
        req->id = id;

        if (inEventLoop()) {
            insertInnerReq(std::move(req));
        } else {
            std::unique_lock lockGuard(mMutex);
            mOuterPostReq[req->id] = std::move(req);
            if (mAsyncReady) {
                uv_async_send(&mAsync);
            }
        }
        return id;
    }

    void cancel(uint64_t id) noexcept {
        if (inEventLoop()) {
            cancelInnerReq(id);
        } else {
            cancelOuterReq(id);
        }
    }

    /**
     * 事实上这个函数根本停不下来，囧
     * 只能用于测试，用来当没有活跃链接时快速退出 EventLoop
     */
    void quit() noexcept {
        post([this]() {
            std::unique_lock lockGuard(mMutex);
            if (mAsyncReady) {
                mAsyncReady = false;
                uv_close(reinterpret_cast<uv_handle_t*>(&mAsync), nullptr);
            }
        });
    }

    bool inEventLoop() const noexcept { return Log::threadId() == mLooperThreadId; }

    uv_loop_t *handle() noexcept { return &mLooper; }

    void setParent(const EventLoopGroupPtr& group) noexcept { mParent = group; }
    EventLoopGroupPtr getParent() noexcept { return mParent.lock(); }
};

class Thread {
    enum State {
        INIT,
        BEGIN,
        LOOP,
    };

    std::thread mThread;
    std::condition_variable mCond;
    std::mutex mMutex;
    EventLoopPtr mLooper;
    volatile State mState = State::INIT;

    static void run(Thread *t) noexcept {
        auto looper = std::make_shared<EventLoop>();
        t->mLooper = looper;
        looper->post([self = t]() {
            std::unique_lock lockGuard(self->mMutex);
            CHECK(self->mState == State::BEGIN, "invalid state: %d", self->mState)
            self->mState = State::LOOP;
            self->mCond.notify_all();
        });
        looper->loop();
    }

public:
    explicit Thread() noexcept = default;
    NO_COPY(Thread)

    EventLoopPtr await() noexcept {
        std::unique_lock lockGuard(mMutex);
        while (true) {
            switch (mState) {
                case State::INIT: {
                    mThread = std::thread(run, this);
                    // 哈哈，一个野线程
                    mThread.detach();
                    mState = State::BEGIN;
                    break;
                }
                case State::BEGIN: {
                    mCond.wait(lockGuard);
                    break;
                }
                case State::LOOP: {
                    return mLooper;
                }
            }
        }
    }
};

class EventLoopGroup: public std::enable_shared_from_this<EventLoopGroup> {
    int mSize = 0;
    std::atomic<int> mIndex = 0;
    std::unique_ptr<EventLoopPtr[]> mEventLoops;
    std::unique_ptr<std::once_flag[]> mOnceFlags;

public:
    explicit EventLoopGroup(int size) noexcept: mSize(size) {
        // std::once_flag 没法移动，不能放到 vector 里
        mEventLoops = std::make_unique<EventLoopPtr[]>(size);
        mOnceFlags = std::make_unique<std::once_flag[]>(size);
    }

    NO_COPY(EventLoopGroup)

    EventLoopPtr next() noexcept {
        auto index = mIndex.fetch_add(1, std::memory_order_relaxed) % mSize;
        std::call_once(mOnceFlags[index], [index, this]() {
            mEventLoops[index] = Thread().await();
            mEventLoops[index]->setParent(shared_from_this());
        });
        return mEventLoops[index];
    }
};
}


#endif // HYSBURG_LOOPER_H