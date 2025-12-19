
#ifndef HYSBURG_FUTURE_HPP
#define HYSBURG_FUTURE_HPP

#include "EventLoop.hpp"

namespace hysburg {


template <typename T>
class Future;
template <typename T>
using FuturePtr = std::shared_ptr<Future<T>>;

template <typename T>
class Promise;
template <typename T>
using PromisePtr = std::shared_ptr<Promise<T>>;

template <typename T>
PromisePtr<T> makePromise(EventLoopPtr loop) noexcept {
    return std::make_shared<Promise<T>>(std::move(loop));
}

template <typename T>
class Future: public std::enable_shared_from_this<Future<T>> {
    struct Listener {
        int id = 0;
        std::function<void(Future<T>&)> cb;
        explicit Listener(int _id, std::function<void(Future<T>&)> _cb)
            : id(_id), cb(std::move(_cb)) {
        }
    };

    enum State {
        INIT,
        SUCCESS,
        FAILURE,
        CANCELED,
    };

    std::atomic<State> mState { State::INIT };
    std::vector<Listener> mListeners;
    EventLoopPtr mExecutor;

    std::mutex mMutex;
    std::condition_variable mCond;
    volatile int mListenerId = 1;

    using ValueType = std::conditional_t<std::is_void_v<T>, std::monostate, T>;
    ValueType mValue {};

    void notifyListeners(std::vector<Listener> listeners) noexcept {
        if (listeners.empty()) {
            return;
        }
        if (mExecutor->inEventLoop()) {
            for (auto &it : listeners) {
                if (it.cb) { it.cb(*this); }
            }
            return;
        }
        // 现在比较麻烦，我们得在 eventLoop 中执行回调
        mExecutor->post([
                self = Future<T>::shared_from_this(),
                listeners = std::move(listeners)
        ]() {
            for (auto &it : listeners) {
                if (it.cb) { it.cb(*self); }
            }
        });
    }

    bool trySetResult(State result, ValueType value) noexcept {
        // 快速返回，这是一个“写入前”的检查，不是“读取后”的消费
        if (mState.load(std::memory_order_relaxed) != State::INIT) {
            return false;
        }
        std::unique_lock lockGuard(mMutex);
        // double check
        if (mState.load(std::memory_order_relaxed) != State::INIT) {
            return false;
        }
        // 先设置 mValue，再使用 release 语义发布
        mValue = std::move(value);
        mState.store(result, std::memory_order_release);
        mCond.notify_all();

        std::vector<Listener> tmp(std::move(mListeners));
        lockGuard.unlock();
        notifyListeners(std::move(tmp));
        return true;
    }

    void setResult(State result, ValueType value) noexcept {
        if (!trySetResult(result, std::move(value))) {
            PLOGE("another value !");
        }
    }
    friend class Promise<T>;
public:
    explicit Future(EventLoopPtr eventLoop) noexcept: mExecutor(std::move(eventLoop)) {
    }

    NO_COPY(Future)

    ~Future() noexcept = default; /* {
        std::unique_lock lockGuard(mMutex);
        CHECK(mListeners.empty(), "active listeners !")
    } */

    [[nodiscard]]
    bool isSuccess() const noexcept { return mState.load(std::memory_order_acquire) == State::SUCCESS; }

    [[nodiscard]]
    bool isFailure() const noexcept { return mState.load(std::memory_order_acquire) == State::FAILURE; }

    [[nodiscard]]
    bool isCanceled() const noexcept { return mState.load(std::memory_order_acquire) == State::CANCELED; }

    [[nodiscard]]
    bool isDone() const noexcept { return mState.load(std::memory_order_acquire) != State::INIT; }

    void await() noexcept {
        std::unique_lock lockGuard(mMutex);
        while (!isDone()) {
            mCond.wait(lockGuard);
        }
    }

    void sync() noexcept {
        await();
        CHECK(isSuccess(), "not success !")
    }

    template<typename E = T>
    std::enable_if_t<!std::is_void_v<E>, E> &get() noexcept {
        CHECK(isSuccess(), "no value available")
        return mValue;
    }

    int addListener(std::function<void(Future<T>&)> cb) noexcept {
        std::unique_lock lockGuard(mMutex);
        auto id = mListeners.emplace_back(mListenerId++, std::move(cb)).id;
        if (isDone()) {
            std::vector<Listener> tmp(std::move(mListeners));
            lockGuard.unlock();
            notifyListeners(std::move(tmp));
        }
        return id;
    }

    void removeListener(int id) noexcept {
        std::unique_lock lockGuard(mMutex);
        for (auto it = mListeners.begin(); it != mListeners.end(); ++it) {
            if (it->id == id) {
                mListeners.erase(it);
                break;
            }
        }
    }
};


template <typename T>
class Promise {
    FuturePtr<T> mFuture;
public:
    explicit Promise(EventLoopPtr eventLoop) noexcept {
        mFuture = std::make_shared<Future<T>>(std::move(eventLoop));
    }
    NO_COPY(Promise)

    ~Promise() noexcept {
        mFuture->trySetResult(Future<T>::CANCELED, typename Future<T>::ValueType());
    }

    template<typename ...Args>
    void setSuccess(Args&&... args) noexcept {
        typename Future<T>::ValueType value(std::forward<Args>(args)...);
        mFuture->setResult(Future<T>::SUCCESS, std::move(value));
    }

    void setFailure() noexcept {
        mFuture->setResult(Future<T>::FAILURE, typename Future<T>::ValueType());
    }

    Future<T> &retain() noexcept { return *mFuture; }
    FuturePtr<T> future() noexcept { return mFuture; }
};


}

#endif

