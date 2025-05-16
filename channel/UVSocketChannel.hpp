#ifndef HYSBURG_UV_SOCKET_CHANNEL_HPP
#define HYSBURG_UV_SOCKET_CHANNEL_HPP

#include "Channel.hpp"

namespace hysburg
{

class UVSocketChannel: public Channel
{
    // 子类的函数访问其它 UVSocketChannel 实例的成员，protected 属性不太行
    friend class UVServerSocketChannel;

    uv_tcp_t mTcp {};
    uv_connect_t mConn {};

    void handleConnectResult(int result) noexcept {
        LOGE("connect to '%s', result='%s(%d)'",
             Net::stringOf(&mRemoteAddress.addr).c_str(),
             uv_err_name(result), result
        );
        if (result != 0) {
            setResult(false, mConnectPromise);
            return;
        }
        activePipeline(mConnectPromise);
    }

    virtual void activePipeline(const PromisePtr<void> &promise) noexcept {
        // 更新 tcp 两端地址
        int localSockLen = sizeof(mLocalAddress);
        uv_tcp_getsockname(&mTcp, &mLocalAddress.addr, &localSockLen);
        int peerSockLen = sizeof(mRemoteAddress);
        uv_tcp_getpeername(&mTcp, &mRemoteAddress.addr, &peerSockLen);

        // 开始读
        int result = uv_read_start((uv_stream_t *) &mTcp, [](uv_handle_t *, size_t suggestedSize, uv_buf_t *buf) {
            buf->base = (char *) ByteBuf::Allocator().alloc(suggestedSize);
            buf->len = suggestedSize;
        }, [](uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
            auto self = static_cast<UVSocketChannel*>(handle->data);
            std::unique_ptr<uint8_t, void(*)(uint8_t *)> ptr(
                    reinterpret_cast<uint8_t*>(buf->base),
                    [](uint8_t *ptr) { ByteBuf::Allocator().free(ptr); }
            );
            if (LIKELY(nread > 0)) {
                auto msg = makeAny<ByteBuf>();
                auto byteBuf = msg->as<ByteBuf>();
                byteBuf->grab(ptr.release(), buf->len);
                byteBuf->writeIndex(nread);
                self->pipeline().fireChannelRead(std::move(msg));
                return ;
            }
            if (nread == UV_EOF) {
                // 对面已经关闭了对面的写端，此时这个 channel 仍然可以认为是活跃的
                return;
            }
            if (nread < 0) {
                self->doClose();
            }
        });

        if (result != 0) {
            LOGE("failed to start tcp read ! err='%s(%d)'",
                 uv_err_name(result), result);
            setResult(false, promise);
            return;
        }
        LOGD("new tcp linking, '%s' <-> '%s'",
             localAddrString().c_str(),
             remoteAddrString().c_str()
        );

        // 流水线，启动！
        mPipeline.fireChannelActive();
        setResult(true, promise);
    }

protected:

    void doRegister() noexcept override {
        mTcp.data = this;
        mConn.data = this;
        auto ret = uv_tcp_init(mExecutor->handle(), &mTcp);
        if (ret != 0) {
            setResult(false, mRegisterPromise);
            return;
        }
        mPipeline.addAllHandlers(mExecutor);
        setResult(true, mRegisterPromise);
    }

    void doBind() noexcept override {
        auto ret = uv_tcp_bind(&mTcp, &mLocalAddress.addr, 0);
        setResult(ret == 0, mBindPromise);
    }

    void doConnect() noexcept override {
        auto ret = uv_tcp_connect(&mConn, &mTcp, &mRemoteAddress.addr, [](uv_connect_t* conn, int status) {
            auto self = static_cast<UVSocketChannel*>(conn->data);
            self->handleConnectResult(status);
        });
        if (ret != 0) {
            setResult(false, mConnectPromise);
        }
    }

    void doOption(hysburg::ChannelOption key, int value) noexcept override {
        switch (key) {
            case ChannelOption::KEEP_ALIVE:
                uv_tcp_keepalive(&mTcp, value, 1);
                break;
            case ChannelOption::NO_DELAY:
                uv_tcp_nodelay(&mTcp, value);
                break;
            default:
                LOGW("unknown channel option: '%d'", value);
                break;
        }
    }

    using WriteOnce = std::pair<AnyPtr, PromisePtr<void>>;
    std::vector<WriteOnce> mWriteQueue;

    void doWrite(hysburg::AnyPtr msg, PromisePtr<void> promise) noexcept override {
        if (UNLIKELY(!msg->is<ByteBuf>())) {
            LOGW("unknown msg type: '%s'", msg->type.name());
            return;
        }
        mWriteQueue.emplace_back(std::move(msg), std::move(promise));
    }

    struct WriteEvent {
        uv_write_t req {};
        std::vector<uv_buf_t> bufQueue;
        std::vector<WriteOnce> msgQueue;
    };

    void doFlush() noexcept override {
        auto event = new WriteEvent;
        event->req.data = event;
        event->msgQueue.swap(mWriteQueue);
        event->bufQueue.resize(event->msgQueue.size());

        for (size_t i = 0; i < event->msgQueue.size(); i ++) {
            auto byteBuf = event->msgQueue[i].first->as<ByteBuf>();
            event->bufQueue[i] = uv_buf_init(
                    reinterpret_cast<char*>(byteBuf->readData()),
                    byteBuf->readableBytes()
            );
        }
        auto ret = uv_write(
                &event->req, reinterpret_cast<uv_stream_t*>(&mTcp),
                event->bufQueue.data(), event->bufQueue.size(),
                [](uv_write_t* req, int status) {
                    auto event = static_cast<WriteEvent*>(req->data);
                    for (auto &pair : event->msgQueue) {
                        setResult(status == 0, pair.second);
                    }
                    delete event;
                }
        );
        if (ret != 0) {
            for (auto &pair : event->msgQueue) {
                setResult(false, pair.second);
            }
            delete event;
        }
    }

    void doReopen(int reopenFd) noexcept {
        auto ret = uv_tcp_open(&mTcp, reopenFd);
        if (ret != 0) {
            doClose();
            return;
        }
        activePipeline(nullptr);
    }

    void doListen(int backlog) noexcept override {
        setResult(false, mListenPromise);
    }

    void doClose() noexcept override {
        if (!mRegisterPromise->retain().isSuccess()) {
            setResult(true, mConnectPromise);
            return;
        }
        // 关闭整条流水线
        if (mPipeline.isActive()) {
            mPipeline.fireChannelInactive();
        }
        mPipeline.removeAllHandlers();
        setResult(true, mCloseFuture);

        // 关闭 socket
        uv_close((uv_handle_t *)&mTcp, [](uv_handle_t* handle) {
            auto self = static_cast<UVSocketChannel *>(handle->data);
            self->mSelf.reset();
        });
    }

public:
    explicit UVSocketChannel() noexcept = default;
    NO_COPY(UVSocketChannel)
};

class UVServerSocketChannel: public UVSocketChannel
{

    static int dupFd(uv_tcp_t *tcp) noexcept {
        uv_os_fd_t fd = -1;
        auto ret = -1;
        if ((ret = uv_fileno(reinterpret_cast<uv_handle_t*>(tcp), &fd)) < 0) {
            LOGE("failed to read fileno: '%s(%d)', close client", uv_err_name(ret), ret);
            return -1;
        }
        if ((ret = dup(fd)) < 0) {
            LOGE("failed to dup socket fd '%d', close client", fd);
            return -1;
        }
        return ret;
    }

    void doAccept() {
        uv_tcp_t client {};
        uv_tcp_init(mTcp.loop, &client);
        std::unique_ptr<uv_tcp_t, void(*)(uv_tcp_t*)> clientGuard(
                &client, [](uv_tcp_t *client) {
                    uv_close(reinterpret_cast<uv_handle_t*>(client), nullptr);
                });

        auto ret = uv_accept((uv_stream_t*) &mTcp, (uv_stream_t*) &client);
        if (ret != 0) {
            LOGW("failed to accept new client, close server");
            clientGuard.reset(); // 先关闭 client 再关闭 server
            doClose();
            return;
        }
        // 新的 channel 要在哪个线程中执行
        auto group = mExecutor->getParent();
        auto executor = group ? group->next() : nullptr;
        if (executor == nullptr) {
            executor = mExecutor;
        }

        // 需要把 client 跨线程传递给 executor.
        // client tcp 是绑定在 mExecutor 线程中的，不能跨线程传递给 client channel
        // 这里是用 dup 文件描述符的方式传递
        int newFd = dupFd(&client);
        clientGuard.reset();

        if (newFd < 0) {
            return;
        }

        auto channel = std::make_shared<UVSocketChannel>();
        channel->registerIn(executor);

        // 先发送到流水线，父类的流水线可能要注入什么 handler 进来
        // 如果后置，注入进来的这些新 handler 将无法得到 channelActive() 回调
        mPipeline.fireChannelRead(makeAny<ChannelPtr>(channel));

        if (executor->inEventLoop()) {
            channel->doReopen(newFd);
        } else {
            executor->post([channel, newFd]() {
                channel->doReopen(newFd);
            });
        }
    }

protected:
    void doConnect() noexcept override {
        setResult(false, mConnectPromise);
    }

    void activePipeline(const PromisePtr<void> &promise) noexcept override {
        // 更新 tcp 两端地址
        int localSockLen = sizeof(mLocalAddress);
        uv_tcp_getsockname(&mTcp, &mLocalAddress.addr, &localSockLen);
        int peerSockLen = sizeof(mRemoteAddress);
        uv_tcp_getpeername(&mTcp, &mRemoteAddress.addr, &peerSockLen);

        // 流水线，启动！
        mPipeline.fireChannelActive();
    }

    void doListen(int backlog) noexcept override {
        auto ret = uv_listen((uv_stream_t *)&mTcp, backlog, [](uv_stream_t* server, int status) {
            auto self = static_cast<UVServerSocketChannel*>(server->data);
            self->doAccept();
        });
        if (ret != 0) {
            setResult(false, mListenPromise);
            return;
        }
        // 这里就要激活流水线了
        activePipeline(nullptr);
        setResult(true, mListenPromise);
    }

public:
    explicit UVServerSocketChannel() noexcept = default;
    NO_COPY(UVServerSocketChannel)
};
}

#endif // HYSBURG_UV_SOCKET_CHANNEL_HPP