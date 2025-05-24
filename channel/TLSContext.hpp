

#ifndef HYSBURG_TLS_CONTEXT
#define HYSBURG_TLS_CONTEXT

#include <string>
#include <vector>
#include <s2n.h>

#include "ChannelHandler.hpp"

namespace hysburg {

class TLSContext;
using TLSContextPtr = std::shared_ptr<TLSContext>;

class TLSContextFactory;
using TLSContextFactoryPtr = std::shared_ptr<TLSContextFactory>;

using TLSMode = s2n_mode;


class TLSContextFactory: public std::enable_shared_from_this<TLSContextFactory> {
    friend class TLSContext;

    s2n_config *mConfig = nullptr;
    std::vector<s2n_cert_chain_and_key*> mCerts;

    static std::string readFile(const std::string_view &path_r) noexcept {
        std::string path_s;
        const char *path = "";
        if (path_r[path_r.size()] == '\0') {
            path = path_r.data();
        } else {
            path_s = path_r;
            path = path_s.data();
        }

        struct stat st {};
        if (::stat(path, &st) != 0) {
            return "";
        }
        std::string result;
        result.reserve(st.st_size);

        std::unique_ptr<FILE, void(*)(FILE*)> fp(
                fopen(path, "rb"),
                [](FILE *fp) { fclose(fp); }
        );
        if (fp == nullptr) {
            fp.release();
            return "";
        }
        std::vector<char> buff(16 * 1024);
        while (!feof(fp.get()) && !ferror(fp.get())) {
            ssize_t bytes = fread(buff.data(), 1, buff.size(), fp.get());
            if (bytes <= 0) {
                break;
            }
            result.append(buff.data(), bytes);
        }
        return result;
    }

public:
    static void initLibrary() {
        static std::once_flag initOnce {};
        std::call_once(initOnce, []() {
            // 禁用 mlock()
            setenv("S2N_DONT_MLOCK", "1", 1);

            // 内存管理
            s2n_mem_set_callbacks(nullptr, nullptr, [](void **ptr, uint32_t requested, uint32_t *allocated) -> int {
                *ptr = ByteBuf::Allocator().alloc(requested);
                *allocated = requested;
                return 0;
            }, [](void *ptr, uint32_t size) -> int {
                ByteBuf::Allocator().free(static_cast<uint8_t*>(ptr));
                return 0;
            });

            // 初始化库
            auto ret = s2n_init();
            CHECK(ret == S2N_SUCCESS, "libs2n init failed: '%d'", ret)

            s2n_stack_traces_enabled_set(true);
        });
    }

    explicit TLSContextFactory() noexcept {
        initLibrary();
        mConfig = s2n_config_new();
    }
    NO_COPY(TLSContextFactory)

    ~TLSContextFactory() noexcept {
        for (auto it : mCerts) {
            s2n_cert_chain_and_key_free(it);
        }
        s2n_config_free(mConfig);
    }

    int addAlpn(const std::string_view &alpn) noexcept {
        return s2n_config_append_protocol_preference(
                mConfig,
                reinterpret_cast<const uint8_t*>(alpn.data()),
                alpn.size()
        );
    }

    int certFile(const std::string_view &certFile, const std::string_view &keyFile) noexcept {
        auto cert = readFile(certFile);
        auto key = readFile(keyFile);
        if (cert.empty() || key.empty()) {
            return -1;
        }
        auto pair = s2n_cert_chain_and_key_new();
        mCerts.push_back(pair);
        return s2n_cert_chain_and_key_load_pem(pair, cert.data(), key.data());
    }

    TLSContextPtr newInstance(TLSMode mode) noexcept;
};


class TLSContext: public std::enable_shared_from_this<TLSContext> {
public:
    using Writer = std::function<ssize_t(const uint8_t *, uint32_t)>;
    using Reader = std::function<ssize_t(uint8_t*, uint32_t)>;
private:
    TLSMode mMode = TLSMode::S2N_CLIENT;
    std::string mSni;
    s2n_connection *mConn = nullptr;
    std::shared_ptr<TLSContextFactory> mFactory;
    Writer mWriter;
    Reader mReader;
    bool mConfigSet = false;

public:
    explicit TLSContext(TLSContextFactory &factory, TLSMode mode) noexcept {
        mMode = mode;
        mFactory = factory.shared_from_this();
        mConn = s2n_connection_new(mode);
        s2n_connection_set_ctx(mConn, this);
        s2n_connection_set_blinding(mConn, S2N_SELF_SERVICE_BLINDING);
    }
    NO_COPY(TLSContext)

    ~TLSContext() noexcept {
        s2n_connection_free(mConn);
    }

    int sni(const std::string_view &sni) noexcept {
        mSni = sni;
        return s2n_set_server_name(mConn, mSni.c_str());
    }

    const std::string &sni() const noexcept { return mSni; }

    int setReader(Reader reader) noexcept {
        mReader.swap(reader);
        s2n_connection_set_recv_ctx(mConn, this);
        s2n_connection_set_recv_cb(mConn, [](void *io_context, uint8_t *buf, uint32_t len) -> int {
            auto self = static_cast<TLSContext*>(io_context);
            if (self->mReader == nullptr) {
                errno = EFAULT;
                return -1;
            }
            auto bytes = self->mReader(buf, len);
            // 返回 0 会被 s2n 认为是 "链接已关闭"
            if (bytes == 0) {
                errno = EAGAIN;
                return -1;
            }
            return (int) bytes;
        });
        return 0;
    }

    int setWriter(Writer writer) noexcept {
        mWriter.swap(writer);
        s2n_connection_set_send_ctx(mConn, this);
        s2n_connection_set_send_cb(mConn, [](void *io_context, const uint8_t *buf, uint32_t len) -> int {
            auto self = static_cast<TLSContext*>(io_context);
            if (self->mWriter == nullptr) {
                errno = EFAULT;
                return -1;
            }
            auto bytes = self->mWriter(buf, len);
            // 返回 0 会被 s2n 认为是 "链接已关闭"
            if (bytes == 0) {
                errno = EAGAIN;
                return -1;
            }
            return (int) bytes;
        });
        return 0;
    }

    int fd(int fd) noexcept {
        return s2n_connection_set_fd(mConn, fd);
    }

    enum HandshakeResult {
        AGAIN,
        OK,
        ERROR,
    };

    const char *errMsg() const noexcept {
        (void) this;
        return s2n_strerror_name(s2n_errno);
    }

    [[nodiscard]]
    HandshakeResult handshake() noexcept {
        if (!mConfigSet) {
            mConfigSet = true;
            s2n_connection_set_config(mConn, mFactory->mConfig);
        }
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        auto ret = s2n_negotiate(mConn, &blocked);
        if (ret == S2N_SUCCESS) {
            return HandshakeResult::OK;
        }
        auto errorType = s2n_error_get_type(s2n_errno);
        if (errorType == S2N_ERR_T_BLOCKED) {
            return HandshakeResult::AGAIN;
        }
        return ERROR;
    }

    ssize_t send(ByteBuf &byteBuf) noexcept {
        auto oldIndex = byteBuf.readIndex();

        while (byteBuf.readableBytes() > 0) {
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            auto bytes = s2n_send(
                    mConn, byteBuf.readData(), byteBuf.readableBytes(), &blocked
            );
            if (bytes > 0) {
                byteBuf.readIndex(byteBuf.readIndex() + bytes);
                continue;
            }
            auto errorType = s2n_error_get_type(s2n_errno);
            if (errorType == S2N_ERR_T_BLOCKED) {
                break;
            }
            return -1;
        }
        return byteBuf.readIndex() - oldIndex;
    }

    ssize_t recv(ByteBuf &byteBuf) noexcept {
        auto oldIndex = byteBuf.writeIndex();
        while (byteBuf.capacity() > byteBuf.writeIndex()) {
            s2n_blocked_status blocked = S2N_NOT_BLOCKED;
            auto bytes = s2n_recv(
                    mConn, byteBuf.writeData(), byteBuf.capacity() - byteBuf.writeIndex(), &blocked
            );
            if (bytes > 0) {
                byteBuf.writeIndex(byteBuf.writeIndex() + bytes);
                continue;
            }
            auto errorType = s2n_error_get_type(s2n_errno);
            if (errorType == S2N_ERR_T_BLOCKED) {
                break;
            }
            return -1;
        }
        return byteBuf.writeIndex() - oldIndex;
    }

    uint64_t shutdownDelay() noexcept {
        // 纳秒转毫秒
        return s2n_connection_get_delay(mConn) / 1000 / 1000;
    }

    void shutdown() noexcept {
        s2n_blocked_status blocked = S2N_NOT_BLOCKED;
        s2n_shutdown(mConn, &blocked);
    }

    TLSMode mode() const noexcept { return mMode; }

    [[nodiscard]]
    bool isClientMode() const noexcept { return mMode == TLSMode::S2N_CLIENT; }
};


class TLSContextHandler: public ChannelDuplexHandler {

    ByteBuf mByteBuff;
    ByteBuf mTmpWriteBuff;
    TLSContextPtr mTLSContext;

    enum State {
        INIT,
        HANDSHAKE,
        OK,
        ERROR,
    };

    State mState = State::INIT;
    uint64_t mShutdownTimerId = 0;

    void decode(ChannelHandlerContext &ctx) noexcept {
        if (mState == State::INIT) {
            onInit(ctx);
        }
        if (mState == State::HANDSHAKE) {
            onHandshake(ctx);
        }
        if (mState == State::OK) {
            onOk(ctx);
        }
        if (mState == State::ERROR) {
            onError(ctx);
        }
    }

    void onInit(ChannelHandlerContext &ctx) noexcept {
        mTLSContext->setReader([this](uint8_t *out, uint32_t outLen) -> ssize_t {
            auto bytes = (ssize_t) mByteBuff.readBytes(out, outLen);
            if (mByteBuff.readableBytes() == 0) {
                mByteBuff.discardReadBytes();
            }
            return bytes;
        });
        mTLSContext->setWriter([&ctx](const uint8_t *in, uint32_t inLen) -> ssize_t {
            if (!ctx.channel().isActive()) {
                return -1;
            }
            if (inLen > 0) {
                auto msg = makeAny<ByteBuf>();
                auto byteBuf = msg->as<ByteBuf>();
                byteBuf->writeBytes(in, inLen);
                ctx.writeAndFlush(std::move(msg));
            }
            return inLen;
        });

        // client 必须设置 sni
        if (mTLSContext->isClientMode() && mTLSContext->sni().empty()) {
            auto &host = ctx.channel().connectHost();
            if (!host.empty()) {
                LOGW("rewrite sni from channel connect name: '%s'", host.c_str());
                mTLSContext->sni(host);
            } else {
                LOGW("empty sni, and failed to rewrite from channel");
            }
        }
        mState = State::HANDSHAKE;
    }

    void onHandshake(ChannelHandlerContext &) noexcept {
        switch (mTLSContext->handshake()) {
            case TLSContext::AGAIN: {
                break;
            }
            case TLSContext::OK: {
                mState = mTLSContext->send(mTmpWriteBuff) < 0 ?
                        State::ERROR : State::OK;
                mTmpWriteBuff.release();
                break;
            }
            case TLSContext::ERROR: {
                LOGW("TLS handshake failed, '%s'", mTLSContext->errMsg());
                mState = State::ERROR;
                break;
            }
        }
    }

    void onOk(ChannelHandlerContext &ctx) noexcept {
        while (true) {
            auto msg = makeAny<ByteBuf>(16 * 1024);
            auto byteBuf = msg->as<ByteBuf>();
            auto ret = mTLSContext->recv(*byteBuf);
            if (ret < 0) {
                LOGW("TLS recv failed, '%s'", mTLSContext->errMsg());
                mState = State::ERROR;
                break;
            }
            if (byteBuf->readableBytes() == 0) {
                break;
            }
            ctx.fireChannelRead(std::move(msg));
        }
    }

    void onError(ChannelHandlerContext &ctx) noexcept {
        if (mShutdownTimerId == 0) {
            auto delayMs = (long ) mTLSContext->shutdownDelay();
            mShutdownTimerId = ctx.channel().executor()->post(delayMs, [&ctx, this]() {
                mTLSContext->shutdown();
                ctx.close();
            });
        }
        mByteBuff.release();
        mTmpWriteBuff.release();
    }

    void removeShutdownTimer(ChannelHandlerContext &ctx) noexcept {
        if (mShutdownTimerId != 0) {
            ctx.channel().executor()->cancel(mShutdownTimerId);
            mShutdownTimerId = 0;
        }
    }

    void encode(ChannelHandlerContext &, ByteBuf &byteBuf, const PromisePtr<void>& promise) noexcept {
        if (mState == State::HANDSHAKE) {
            mTmpWriteBuff.cumulate(byteBuf);
            if (promise) { promise->setSuccess(); }
        }
        if (mState == State::OK) {
            if (mTLSContext->send(byteBuf) < 0) {
                mState = State::ERROR;
            } else if (promise) {
                promise->setSuccess();
            }
        }
        if (mState == State::ERROR) {
            if (promise) { promise->setFailure(); }
        }
    }

public:
    void handlerAdded(ChannelHandlerContext &ctx) noexcept override {
        if (mTLSContext->isClientMode() && ctx.channel().isActive()) {
            decode(ctx);
        }
    }

    void channelActive(hysburg::ChannelHandlerContext &ctx) noexcept override {
        if (mTLSContext->isClientMode()) {
            decode(ctx);
        }
        ctx.fireChannelActive();
    }

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override {
        if (!msg->is<ByteBuf>()) {
            ctx.fireChannelRead(std::move(msg));
            return;
        }
        mByteBuff.cumulate(*msg->as<ByteBuf>());
        decode(ctx);
    }

    void handlerRemoved(ChannelHandlerContext &ctx) noexcept override {
        removeShutdownTimer(ctx);
    }

    void channelInactive(ChannelHandlerContext &ctx) noexcept override {
        ctx.fireChannelInactive();
        removeShutdownTimer(ctx);
    }

    void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) noexcept override {
        if (!msg->is<ByteBuf>()) {
            ctx.write(std::move(msg), std::move(promise));
            return;
        }
        encode(ctx, *msg->as<ByteBuf>(), promise);
    }

    void flush(ChannelHandlerContext &ctx) noexcept override {
        /* no-op */
    }

    void close(ChannelHandlerContext &ctx) noexcept override {
        if (mState != State::ERROR) {
            mTLSContext->shutdown();
        }
        ctx.close();
    }

    explicit TLSContextHandler(const TLSContextFactoryPtr &factory, TLSMode mode) noexcept {
        mTLSContext = factory->newInstance(mode);
    }
    NO_COPY(TLSContextHandler)

    [[nodiscard]]
    TLSContextPtr tlsContext() noexcept { return mTLSContext; }
};

}

#endif // HYSBURG_TLS_CONTEXT
