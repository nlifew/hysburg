
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
        uint64_t delay = 0;
        uv_timer_t timer {};
        std::function<void()> rcb;
    };

    uint64_t mLooperThreadId = 0;
    uv_loop_t mLooper {};

    std::mutex mMutex;
    uv_async_t mAsync {};

    std::vector<std::unique_ptr<PostReq>> mQueue;
    std::weak_ptr<EventLoopGroup> mParent;


    void flushOuterReq() {
        std::vector<std::unique_ptr<PostReq>> cpy; {
            std::unique_lock lockGuard(mMutex);
            cpy.swap(mQueue);
        }
        for (auto &_it : cpy) {
            auto it = _it.release();
            uv_timer_init(&mLooper, &it->timer);
            it->timer.data = it;
            uv_timer_start(
                    &it->timer,
                    [](uv_timer_t *tm) {
                        auto req = static_cast<PostReq*>(tm->data);
                        if (req->rcb != nullptr) { req->rcb(); }
                        uv_close(reinterpret_cast<uv_handle_t*>(tm), [](uv_handle_t *ptr) {
                            delete static_cast<PostReq*>(ptr->data);
                        });
                    },
                    it->delay,
                    0
            );
        }
    }

public:
    explicit EventLoop() = default;
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
        mLooperThreadId = Log::threadId();
        lockGuard.unlock();

        // 正在队列中的临时事件需要插入进去
        flushOuterReq();

        // 开始循环
        uv_run(&mLooper, UV_RUN_DEFAULT);

        // 已经退出，销毁掉资源
        lockGuard.lock();
        uv_loop_close(&mLooper);
        mLooperThreadId = 0;
    }

    void post(std::function<void()> cb) {
        post(0, std::move(cb));
    }

    void post(long ms, std::function<void()> cb) {
        auto req = std::make_unique<PostReq>();
        req->rcb.swap(cb);
        req->delay = ms;

        std::unique_lock lockGuard(mMutex);
        mQueue.emplace_back(std::move(req));
        if (mLooperThreadId != 0) {
            uv_async_send(&mAsync);
        }
    }

    bool inEventLoop() const { return Log::threadId() == mLooperThreadId; }

    uv_loop_t *handle() { return &mLooper; }

    void setParent(const EventLoopGroupPtr& group) { mParent = group; }
    EventLoopGroupPtr getParent() { return mParent.lock(); }
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

    static void run(Thread *t) {
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
    explicit Thread() = default;
    NO_COPY(Thread)

    EventLoopPtr await() {
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
    explicit EventLoopGroup(int size) {
        mSize = std::max(1, size);
        // std::once_flag 没法移动，不能放到 vector 里
        mEventLoops = std::make_unique<EventLoopPtr[]>(mSize);
        mOnceFlags = std::make_unique<std::once_flag[]>(mSize);
    }

    NO_COPY(EventLoopGroup)

    EventLoopPtr next() {
        auto index = mIndex.fetch_add(1, std::memory_order_relaxed) % mSize;
        std::call_once(mOnceFlags[index], [index, this]() {
            mEventLoops[index] = Thread().await();
            mEventLoops[index]->setParent(shared_from_this());
        });
        return mEventLoops[index];
    }
};
}


#endif // HYSBURG_EVENT_LOOP_H