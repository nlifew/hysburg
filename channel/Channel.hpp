#ifndef HYSBURG_CHANNEL_H
#define HYSBURG_CHANNEL_H

#include <string>
#include <vector>
#include <list>
#include <future>
#include <mutex>
#include <unistd.h>

#include "Any.hpp"
#include "ByteBuf.hpp"
#include "Future.hpp"

namespace hysburg {


class ChannelHandlerContext;
class ChannelHandler;
class ChannelPipeline;
class Channel;

using ChannelPtr = std::shared_ptr<Channel>;
using ChannelHandlerPtr = std::shared_ptr<ChannelHandler>;

union SocketAddress {
    sockaddr addr;
    sockaddr_in in;
    sockaddr_in6 in6;
    sockaddr_storage storage;
};


class DnsRequest {
    uv_getaddrinfo_t mReq {};
    std::string mName;
    std::string mPorts;
    uint16_t mPort = 0;
    struct addrinfo mHints {};
    Promise<SocketAddress> mPromise;
    EventLoopPtr mExecutor;
    uint64_t mBeginTime = 0;

    int parseDnsResponse(int status, struct addrinfo* res) {
        if (status != 0 || res == nullptr) {
            LOGE("failed to resolve dns for '%s:%d': %s(%d)",
                 mName.c_str(), mPort,
                 uv_err_name(status), status);
            return -1;
        }
        SocketAddress dest {};
        switch (res->ai_family) {
            case AF_INET: {
                memcpy(&dest.in, res->ai_addr, sizeof(sockaddr_in));
                dest.in.sin_port = htons(mPort);
                break;
            }
            case AF_INET6: {
                memcpy(&dest.in6, res->ai_addr, sizeof(sockaddr_in6));
                dest.in6.sin6_port = htons(mPort);
                break;
            }
            default: {
                LOGE("unknown dns family '%d' for '%s:%d': %d",
                     res->ai_family, mName.c_str(), mPort, res->ai_family);
                return -1;
            }
        }
        LOGI("dns resolve ok, '%s' -> '%s', cost '%llu' ms.",
             mName.c_str(), Net::stringOf(&dest.addr).c_str(),
             Log::currentTimeMillis() - mBeginTime
        );
        mPromise.setSuccess(dest);
        return 0;
    }

    static void doRemoteResolve(DnsRequest *request) {
        LOGI("dns resolve start: '%s:%d'", request->mName.c_str(), request->mPort);
        request->mBeginTime = Log::currentTimeMillis();

        auto ret = uv_getaddrinfo(
                request->mExecutor->handle(),
                &request->mReq,
                [](uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
                    auto request = static_cast<DnsRequest*>(req->data);
                    request->parseDnsResponse(status, res);
                    uv_freeaddrinfo(res);
                    delete request;
                },
                request->mName.c_str(),
                request->mPorts.c_str(),
                &request->mHints
        );
        if (ret != 0) {
            request->mPromise.setFailure();
            delete request;
        }
    }

public:
    explicit DnsRequest(EventLoopPtr &executor):
            mPromise(executor), mExecutor(executor) {
        mHints.ai_family = PF_INET;
        mHints.ai_socktype = SOCK_STREAM;
        mHints.ai_protocol = IPPROTO_TCP;
    }

    NO_COPY(DnsRequest)

    static int localResolve(
            const std::string_view &host, uint16_t port,
            SocketAddress &dest
    ) {
        if (uv_ip4_addr(host.data(), port, &dest.in) == 0) {
            return 0;
        }
        if (uv_ip6_addr(host.data(), port, &dest.in6) == 0) {
            return 0;
        }
        return -1;
    }

    static FuturePtr<SocketAddress> remoteResolve(const std::string_view &host, uint16_t port, EventLoopPtr &executor) {
        auto request = new DnsRequest(executor);
        request->mReq.data = request;
        request->mName = host;
        request->mPort = port;
        request->mPorts = std::to_string(port);

        // 先持有 future，防止 doRemoteResolve 时把 request delete 掉
        auto future = request->mPromise.future();
        if (executor->inEventLoop()) {
            doRemoteResolve(request);
        } else {
            executor->post([request]() {
                doRemoteResolve(request);
            });
        }
        return future;
    }

    static FuturePtr<SocketAddress> resolve(const std::string_view &host, uint16_t port, EventLoopPtr executor) {
        SocketAddress dest {};
        if (localResolve(host, port, dest) == 0) {
            Promise<SocketAddress> promise(executor);
            promise.setSuccess(dest);
            return promise.future();
        }
        return remoteResolve(host, port, executor);
    }
};

class ChannelHandler {
    uint32_t mFlag = 0;
public:
    static constexpr uint32_t FLAG_INBOUNDS = 1 << 0;
    static constexpr uint32_t FLAG_OUTBOUNDS = 1 << 1;

    virtual void handlerAdded(ChannelHandlerContext &ctx) { (void) ctx; }
    virtual void handlerRemoved(ChannelHandlerContext &ctx) { (void) ctx; }

    virtual void channelActive(ChannelHandlerContext &ctx);
    virtual void channelRead(ChannelHandlerContext &ctx, AnyPtr msg);
    virtual void userEventTriggered(ChannelHandlerContext &ctx, AnyPtr msg);
    virtual void channelInactive(ChannelHandlerContext &ctx);

//    virtual void connect(ChannelHandlerContext &ctx, SocketAddress &address);
//    virtual void accept(ChannelHandlerContext &ctx, ChannelPtr channel);
    virtual void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise);
    virtual void flush(ChannelHandlerContext &ctx);
    virtual void close(ChannelHandlerContext &ctx);


    explicit ChannelHandler(uint32_t flag): mFlag(flag) {
    }
    NO_COPY(ChannelHandler)
    virtual ~ChannelHandler() = default;

    [[nodiscard]]
    bool isInbounds() const { return mFlag & FLAG_INBOUNDS; }

    [[nodiscard]]
    bool isOutbounds() const { return mFlag & FLAG_OUTBOUNDS; }

    [[nodiscard]]
    bool isDuplicate() const { return mFlag & (FLAG_INBOUNDS|FLAG_OUTBOUNDS); }
};


class ChannelHandlerContext {
    friend class ChannelPipeline;

    ChannelHandlerContext *mPrev = nullptr;
    ChannelHandlerContext *mNext = nullptr;
    std::string mName;
    ChannelHandlerPtr mHandler;
    EventLoopPtr mExecutor;
    Channel *mChannel = nullptr;
    int mAddedCount = 0;

    [[nodiscard]]
    ChannelHandlerContext *findNextInbounds() {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        for (auto i = mNext; i != nullptr; i = i->mNext) {
            if (i->mHandler->isInbounds()) {
                return i;
            }
        }
        return nullptr;
    }

    [[nodiscard]]
    ChannelHandlerContext *findNextOutbounds() {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        for (auto i = mPrev; i != nullptr; i = i->mPrev) {
            if (i->mHandler->isOutbounds()) {
                return i;
            }
        }
        return nullptr;
    }

    void callHandlerAdded(EventLoopPtr eventLoop) {
        CHECK(mAddedCount == 0, "duplicated add !")
        mAddedCount += 1;
        mExecutor.swap(eventLoop);
        mHandler->handlerAdded(*this);
    }
    void callChannelActive() {
        mHandler->channelActive(*this);
    }
    void callChannelRead(AnyPtr msg) {
        mHandler->channelRead(*this, std::move(msg));
    }
    void callUserEvent(AnyPtr msg) {
        mHandler->userEventTriggered(*this, std::move(msg));
    }
    void callChannelInactive() {
        mHandler->channelInactive(*this);
    }
    void callWrite(AnyPtr msg, PromisePtr<void> promise) {
        mHandler->write(*this, std::move(msg), std::move(promise));
    }
    void callFlush() {
        mHandler->flush(*this);
    }
    void callClose() {
        mHandler->close(*this);
    }
    void callHandlerRemoved() {
        mAddedCount -= 1;
        mHandler->handlerRemoved(*this);
    }

public:
    explicit ChannelHandlerContext(Channel *channel): mChannel(channel) {
    }

    NO_COPY(ChannelHandlerContext)

    [[nodiscard]]
    const std::string &name() const { return mName; }

    [[nodiscard]]
    Channel &channel() const { return *mChannel; }

    [[nodiscard]]
    ChannelPipeline &pipeline() const;

    template<typename T>
    PromisePtr<T> newPromise();

    [[nodiscard]]
    bool isRemoved() const { return mAddedCount <= 0; }

    void fireChannelActive() {
        auto ctx = findNextInbounds();
        if (ctx) { ctx->callChannelActive(); }
    }

    void fireChannelRead(AnyPtr msg) {
        auto ctx = findNextInbounds();
        if (ctx) { ctx->callChannelRead(std::move(msg)); }
    }

    void fireUserEvent(AnyPtr msg) {
        auto ctx = findNextInbounds();
        if (ctx) { ctx->callUserEvent(std::move(msg)); }
    }

    void fireChannelInactive() {
        auto ctx = findNextInbounds();
        if (ctx) { ctx->callChannelInactive(); }
    }

//    void connect(SocketAddress &address) {
//        auto ctx = findNextOutbounds();
//        if (ctx) { ctx->mHandler->connect(*ctx, address); }
//    }
//
//    void accept(ChannelPtr channel) {
//        auto ctx = findNextOutbounds();
//        if (ctx) { ctx->mHandler->accept(*ctx, std::move(channel)); }
//    }

    void writeAndFlush(AnyPtr msg) {
        writeAndFlush(std::move(msg), nullptr);
    }

    void writeAndFlush(AnyPtr msg, PromisePtr<void> promise) {
        write(std::move(msg), std::move(promise));
        flush();
    }

    void write(AnyPtr msg, PromisePtr<void> promise) {
        auto ctx = findNextOutbounds();
        if (ctx) { ctx->mHandler->write(*ctx, std::move(msg), std::move(promise)); }
    }

    void flush() {
        auto ctx = findNextOutbounds();
        if (ctx) { ctx->mHandler->flush(*ctx); }
    }

    void close() {
        auto ctx = findNextOutbounds();
        if (ctx) { ctx->mHandler->close(*ctx); }
    }
};

/**
 * 线程不安全的类，只能在 channel 注册到 eventLoop 之后才能调
 * 为什么呢因为这样写起来简单
 */
class ChannelPipeline {
    std::list<ChannelHandlerContext*> mPending;
    ChannelHandlerContext *mHead = nullptr;
    ChannelHandlerContext *mTail = nullptr;
    Channel *mChannel = nullptr;
    EventLoopPtr mExecutor = nullptr;

    enum State {
        // 初始状态
        INIT = 0,
        // 所有 ChannelHandler 已经注册到 Pipeline
        ADDED = 1,
        // channel 已经链接好
        ACTIVE = 2,
        // channel 关闭
        INACTIVE = 3,
        // 所有的 ChannelHandler 都已经移除
        REMOVED = 4,
    };
    volatile State mState = State::INIT;

    void doInsert(
            ChannelHandlerContext *prev,
            std::string name,
            ChannelHandlerPtr handler
    ) {
        auto ctx = new ChannelHandlerContext(mChannel);
        ctx->mName.swap(name);
        ctx->mHandler.swap(handler);

        auto *next = prev ? prev->mNext: mHead;
        ctx->mPrev = prev;
        ctx->mNext = next;

        if (prev == nullptr) {
            mHead = ctx;
        } else {
            prev->mNext = ctx;
        }
        if (next == nullptr) {
            mTail = ctx;
        } else {
            next->mPrev = ctx;
        }
        if (mState == State::INIT) {
            mPending.push_back(ctx);
            return;
        }
        ctx->callHandlerAdded(mExecutor);
    }

    void doRemove(ChannelHandlerContext *ctx) {
        // 从双向链表中删除
        auto prev = ctx->mPrev;
        auto next = ctx->mNext;

        if (prev != nullptr) { prev->mNext = next; }
        if (next != nullptr) { next->mPrev = prev; }
        if (ctx == mHead) { mHead = next; }
        if (ctx == mTail) { mTail = prev; }

        // 先保留 ctx->mPrev 和 ctx->mNext，这样这个 ctx 仍然能向前/向后发送数据
        // ctx->mPrev = ctx->mNext = nullptr;
        if (mState == State::INIT) {
            auto it = std::find(mPending.begin(), mPending.end(), ctx);
            if (it != mPending.end()) { mPending.erase(it);}
            return;
        }
        ctx->callHandlerRemoved();
        // 延迟 delete：handler 仍然有机会执行一些操作，不至于立即被析构
        mExecutor->post([ctx]() { delete ctx; });
    }

    void initHeadAndTail();

public:
    explicit ChannelPipeline(Channel *channel): mChannel(channel) {
        initHeadAndTail();
    }

    NO_COPY(ChannelPipeline)
    ~ChannelPipeline() = default;

    template <typename T, typename ...Args>
    ChannelPipeline &emplaceLast(Args&&... args)
    {
        return addLast(typeid(T).name(), std::make_shared<T>(std::forward<Args>(args)...));
    }

    ChannelPipeline &addLast(ChannelHandlerPtr handler) {
        return addLast(typeid(handler.get()).name(), std::move(handler));
    }

    ChannelPipeline &addLast(std::string name, ChannelHandlerPtr handler) {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        doInsert(mTail->mPrev, std::move(name), std::move(handler));
        return *this;
    }

    void remove(ChannelHandler *handler) {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        for (auto i = mHead; i != nullptr; i = i->mNext) {
            if (i->mHandler.get() == handler) {
                doRemove(i);
                break;
            }
        }
    }

    void addAllHandlers(const EventLoopPtr &eventLoop) {
        mExecutor = eventLoop;
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        CHECK(mState == State::INIT, "invalid state: '%d'", mState)
        mState = State::ADDED;

        while (!mPending.empty()) {
            auto ctx = mPending.front();
            mPending.pop_front();
            ctx->callHandlerAdded(eventLoop);
        }
    }

    void removeAllHandlers() {
        // 此时 mState 可能处于任何状态：Added，Active, InActive
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        CHECK(State::ADDED <= mState && mState <= State::INACTIVE,
              "invalid state: '%d'", mState)
        mState = State::REMOVED;

        while (mHead != nullptr) {
            doRemove(mHead);
        }
    }

    void fireChannelActive() {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        CHECK(mState == State::ADDED, "invalid state: '%d'", mState)
        mState = State::ACTIVE;
        mHead->callChannelActive();
    }

    void fireChannelRead(AnyPtr msg) {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        CHECK(mState == State::ACTIVE, "invalid state: '%d'", mState)
        mHead->callChannelRead(std::move(msg));
    }

    void fireChannelInactive() {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        CHECK(mState == State::ACTIVE, "invalid state: '%d'", mState)
        mState = State::INACTIVE;
        mHead->callChannelInactive();
    }

    void fireUserEvent(AnyPtr msg) {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        mHead->callUserEvent(std::move(msg));
    }

    void writeAndFlush(AnyPtr msg) {
        writeAndFlush(std::move(msg), nullptr);
    }

    void writeAndFlush(AnyPtr msg, PromisePtr<void> promise) {
        write(std::move(msg), std::move(promise));
        flush();
    }

    void write(AnyPtr msg, PromisePtr<void> promise) {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        CHECK(mState == State::ACTIVE, "invalid state: '%d'", mState)
        mTail->callWrite(std::move(msg), std::move(promise));
    }

    void flush() {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        CHECK(mState == State::ACTIVE, "invalid state: '%d'", mState)
        mTail->callFlush();
    }

    void close() {
        CHECK(mExecutor->inEventLoop(), "cross thread call is DISABLED")
        // 按理说此时应该有其他别的状态的
//        CHECK(mState == State::ACTIVE, "invalid state: '%d'", mState)
        mTail->callClose();
    }

    [[nodiscard]]
    bool isActive() const { return mState == State::ACTIVE; }

    [[nodiscard]]
    bool isRemoved() const { return mState == State::REMOVED; }
};

enum ChannelOption {
    NO_DELAY,
    KEEP_ALIVE,
};

/**
 * 表示对端已经调用 shutdown 关闭了写入
 */
struct ShutdownEvent {};


class Channel: public std::enable_shared_from_this<Channel> {
protected:
    friend struct HeadHandler;
    ChannelPipeline mPipeline;

    /**
     * 下面这几个字段在 [registerIn] 执行前为 nullptr
     */
    PromisePtr<void> mRegisterPromise;
    PromisePtr<void> mCloseFuture;
    PromisePtr<void> mBindPromise;
    PromisePtr<void> mConnectPromise;
    PromisePtr<void> mListenPromise;

    EventLoopPtr mExecutor;
    ChannelPtr mSelf; // 持有一个自己的强引用

    SocketAddress mLocalAddress {};
    SocketAddress mRemoteAddress {};

    std::string mConnectHost;
    uint16_t mConnectPort = 0;

    static void setResult(bool ok, const PromisePtr<void> &promise) {
        if (promise == nullptr) {
            return;
        }
        if (ok) {
            promise->setSuccess();
        } else {
            promise->setFailure();
        }
    }

    virtual void doRegister() = 0;

    virtual void doBind() = 0;

    virtual void doConnect() = 0;

    virtual void doOption(ChannelOption key, int value) = 0;

    virtual void doWrite(AnyPtr msg, PromisePtr<void> promise) = 0;

    virtual void doFlush() = 0;

    virtual void doListen(int backlog) = 0;

    virtual void doClose() = 0;

public:
    explicit Channel(): mPipeline(this) {
        LOGD("channel() = %p", this);
    }

    NO_COPY(Channel)
    virtual ~Channel() {
        LOGD("~Channel() = %p", this);
    }

    FuturePtr<void> registerIn(EventLoopPtr &eventLoop) {
        CHECK(eventLoop != nullptr, "null eventLoop")

        mSelf = shared_from_this();
        mExecutor = eventLoop;

        mRegisterPromise = makePromise<void>(mExecutor);
        mCloseFuture = makePromise<void>(mExecutor);
        mBindPromise = makePromise<void>(mExecutor);
        mConnectPromise = makePromise<void>(mExecutor);
        mListenPromise = makePromise<void>(mExecutor);

        if (mExecutor->inEventLoop()) {
            doRegister();
        } else {
            mExecutor->post([self = mSelf]() {
                self->doRegister();
            });
        }
        return mRegisterPromise->future();
    }

    FuturePtr<void> bind(const std::string_view &host, uint16_t port) {
        SocketAddress address {};
        if (DnsRequest::localResolve(host, port, address) != 0) {
            setResult(false, mBindPromise);
            return mBindPromise->future();
        }
        return bind(address);
    }

    FuturePtr<void> bind(SocketAddress &socketAddress) {
        mLocalAddress = socketAddress;
        if (mExecutor->inEventLoop()) {
            doBind();
        } else {
            mExecutor->post([self = mSelf]() {
                self->doBind();
            });
        }
        return mBindPromise->future();
    }

    FuturePtr<void> connect(const std::string_view &host, uint16_t port) {
        mConnectHost = host;
        mConnectPort = port;

        auto future = DnsRequest::resolve(host, port, mExecutor);
        future->addListener([self = mSelf](auto &future) {
            if (!future.isSuccess()) {
                setResult(false, self->mConnectPromise);
                return ;
            }
            self->connect(future.get());
        });
        return mConnectPromise->future();
    }

    FuturePtr<void> connect(SocketAddress &socketAddress) {
        mRemoteAddress = socketAddress;
        if (mExecutor->inEventLoop()) {
            doConnect();
        } else {
            mExecutor->post([self = mSelf]() {
                self->doConnect();
            });
        }
        return mConnectPromise->future();
    }

    FuturePtr<void> listen(int backlog) {
        if (mExecutor->inEventLoop()) {
            doListen(backlog);
        } else {
            mExecutor->post([self = mSelf, backlog]() {
                self->doListen(backlog);
            });
        }
        return mListenPromise->future();
    }

    void option(ChannelOption key, int value) {
        if (mExecutor->inEventLoop()) {
            doOption(key, value);
            return;
        }
        mExecutor->post([self = mSelf, key, value] {
            self->doOption(key, value);
        });
    }

//    不暴露 close()、write()、flush() 等函数，只能在 pipeline 里访问
//    void close() {
//        // 想了一下确实应该放在 eventLoop 里……鬼知道队列里是不是还有 bind、connect 什么的
//        mRegisterPromise->future().addListener<Channel>(this, [](Future&, Channel *self) {
//            self->doClose();
//        });
//    }


    EventLoopPtr executor() { return mExecutor; }
    ChannelPipeline &pipeline() { return mPipeline; }
    FuturePtr<void> closeFuture() { return mCloseFuture->future(); }

    template<typename E>
    PromisePtr<E> newPromise() { return makePromise<E>(mExecutor); }

    const SocketAddress &localAddress() const { return mLocalAddress; }
    const SocketAddress &remoteAddress() const { return mRemoteAddress; }

    const std::string &connectHost() const { return mConnectHost; }
    uint16_t connectPort() const { return mConnectPort; }

    bool isActive() const { return mPipeline.isActive(); }

    std::string localAddrString() const {
        return Net::toString(&mLocalAddress.addr);
    }

    std::string remoteAddrString() const {
        return Net::toString(&mRemoteAddress.addr);
    }

    std::function<void(Future<void>&)> closeOnFailure() {
        return [self = mSelf](Future<void> &future) {
            if (future.isFailure()) {
                self->pipeline().close();
            }
        };
    }
};

template <typename T>
class Bootstrap {
    ChannelPtr mChannel;
    EventLoopPtr mExecutor;

    void initAndRegister() {
        if (mChannel != nullptr) {
            return;
        }
        CHECK(mExecutor, "no EventLoop instance provided !")
        mChannel = std::make_shared<T>();
        mChannel->registerIn(mExecutor);
    }

public:
    explicit Bootstrap() = default;
    NO_COPY(Bootstrap)

    Bootstrap &eventLoop(EventLoopPtr ptr) {
        mExecutor.swap(ptr);
        return *this;
    }

    Bootstrap &option(ChannelOption option, int value) {
        initAndRegister();
        mChannel->option(option, value);
        return *this;
    }

    Bootstrap &handler(ChannelHandlerPtr handler) {
        initAndRegister();
        if (mChannel->executor()->inEventLoop()) {
            mChannel->pipeline().addLast(std::move(handler));
            return *this;
        }
        mChannel->executor()->post([channel = mChannel, handler] {
            channel->pipeline().addLast(handler);
        });
        return *this;
    }

    template<typename E, typename ...Args>
    Bootstrap &emplaceHandler(Args&&... args) {
        return handler(std::make_shared<E>(std::forward<Args>(args)...));
    }

    FuturePtr<void> bind(SocketAddress &address) {
        initAndRegister();
        return mChannel->bind(address);
    }

    FuturePtr<void> bind(const std::string_view &host, uint16_t port) {
        initAndRegister();
        return mChannel->bind(host, port);
    }

    FuturePtr<void> connect(SocketAddress &address) {
        initAndRegister();
        return mChannel->connect(address);
    }

    FuturePtr<void> connect(const std::string_view &host, uint16_t port) {
        initAndRegister();
        return mChannel->connect(host, port);
    }

    Bootstrap &channel(Channel **out) {
        initAndRegister();
        *out = mChannel.get();
        return *this;
    }
};

template <typename T>
class ServerBootstrap {
    ChannelPtr mChannel;
    EventLoopPtr mExecutor;

    std::vector<std::pair<ChannelOption, int>> mChildOption;

    void initAndRegister() {
        if (mChannel != nullptr) {
            return;
        }
        CHECK(mExecutor, "no EventLoop instance provided !")
        mChannel = std::make_shared<T>();
        mChannel->registerIn(mExecutor);
    }

    struct AcceptHandler: public ChannelHandler {

        ChannelHandlerPtr mHandler;

        void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) override {
            if (!msg->is<ChannelPtr>()) {
                ctx.fireChannelRead(std::move(msg));
                return;
            }
            auto &channel = *msg->as<ChannelPtr>();
            auto executor = channel->executor();
            if (executor->inEventLoop()) {
                channel->pipeline().addLast(mHandler);
                return;
            }
            executor->post([channel, handler = mHandler](){
                channel->pipeline().addLast(handler);
            });
        }

        explicit AcceptHandler(ChannelHandlerPtr hdl):
            ChannelHandler(ChannelHandler::FLAG_INBOUNDS),
            mHandler(std::move(hdl)) {
        }
    };

public:
    explicit ServerBootstrap() = default;
    NO_COPY(ServerBootstrap)

    ServerBootstrap &eventLoop(EventLoopPtr executor) {
        mExecutor.swap(executor);
        return *this;
    }

    ServerBootstrap &eventLoop(const EventLoopGroupPtr &group) {
        return eventLoop(group->next());
    }

    ServerBootstrap &handler(ChannelHandlerPtr handler) {
        if (handler == nullptr) {
            return *this;
        }
        initAndRegister();
        if (mExecutor->inEventLoop()) {
            mChannel->pipeline().addLast(std::move(handler));
        } else {
            mExecutor->post([channel = mChannel, handler]() {
                channel->pipeline().addLast(handler);
            });
        }
        return *this;
    }

    template<typename E, typename ...Args>
    ServerBootstrap &childHandler(Args&&... args) {
        initAndRegister();
        auto handler = std::make_shared<E>(std::forward<Args>(args)...);
        if (mExecutor->inEventLoop()) {
            mChannel->pipeline().template emplaceLast<AcceptHandler>(std::move(handler));
        } else {
            mExecutor->post([channel = mChannel, handler]() {
                channel->pipeline().template emplaceLast<AcceptHandler>(handler);
            });
        }
        return *this;
    }

    FuturePtr<void> bind(SocketAddress &address) {
        initAndRegister();
        return mChannel->bind(address);
    }

    FuturePtr<void> bind(const std::string_view &host, uint16_t port) {
        initAndRegister();
        return mChannel->bind(host, port);
    }

    FuturePtr<void> listen(int backlog) {
        initAndRegister();
        return mChannel->listen(backlog);
    }

    ServerBootstrap& channel(Channel **out) {
        initAndRegister();
        *out = mChannel.get();
        return *this;
    }
};

}

#endif