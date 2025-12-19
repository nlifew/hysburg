

#ifndef HYSBURG_TLS_CONTEXT
#define HYSBURG_TLS_CONTEXT

#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ChannelHandler.hpp"

namespace hysburg {

class TLSContext;
using TLSContextPtr = std::shared_ptr<TLSContext>;

class TLSContextFactory;
using TLSContextFactoryPtr = std::shared_ptr<TLSContextFactory>;

enum TLSMode {
    S2N_SERVER,
    S2N_CLIENT,
};


class TLSContext: public std::enable_shared_from_this<TLSContext> {
private:
    SSL *mSSL = nullptr;
    BIO *mReaderBio = nullptr;
    BIO *mWriterBio = nullptr;
    TLSMode mMode = TLSMode::S2N_CLIENT;

    /**
     * 低版本中 SSL_set_tlsext_host_name() 似乎不会执行 strdup() 而是直接使用
     * 开发者传进去的指针，但不是很确定。此处保险起见放一个 std::string
     */
    std::string mHost;

public:
    explicit TLSContext(SSL *ssl, TLSMode mode) {
        mSSL = ssl;
        mMode = mode;
        mReaderBio = BIO_new(BIO_s_mem());
        mWriterBio = BIO_new(BIO_s_mem());

        SSL_set0_rbio(mSSL, mReaderBio);
        SSL_set0_wbio(mSSL, mWriterBio);

        if (mode == TLSMode::S2N_CLIENT) {
            SSL_set_connect_state(mSSL);
            SSL_set_verify(mSSL, SSL_VERIFY_PEER, nullptr);
        } else {
            SSL_set_accept_state(mSSL);
        }
    }

    NO_COPY(TLSContext)

    ~TLSContext() {
        SSL_free(mSSL);
    }

    enum HandshakeResult {
        AGAIN,
        OK,
        ERROR,
    };

    [[nodiscard]]
    HandshakeResult handshake() {
        auto ret = SSL_do_handshake(mSSL);
        if (ret == 1) {
            LOGI("SSL handshake ok");
            return HandshakeResult::OK;
        }
        if (ret < 0) {
            ret = SSL_get_error(mSSL, ret);
            if (ret == SSL_ERROR_WANT_READ || ret == SSL_ERROR_WANT_WRITE) {
                return HandshakeResult::AGAIN;
            }
        }
        std::string stacktrace;

        unsigned long e;
        while ((e = ERR_get_error()) != 0) {
            char buf[256] = { 0 };
            ERR_error_string_n(e, buf, sizeof(buf));
            stacktrace += buf;
            stacktrace += "\n";
        }
        LOGE("ssl handshake failed: \n%s", stacktrace.c_str());
        return HandshakeResult::ERROR;
    }

    void send(ByteBuf &byteBuf) {
        auto ret = SSL_write(mSSL, byteBuf.readData(), byteBuf.readableBytes());
        if (ret > 0) {
            byteBuf.readIndex(byteBuf.readIndex() + ret);
        }
    }

    void recv(ByteBuf &byteBuf) {
        char buff[4096];
        while (true) {
            auto bytes = SSL_read(mSSL, buff, sizeof(buff));
            if (bytes <= 0) {
                break;
            }
            byteBuf.writeBytes(buff, bytes);
        }
    }

    long pendingReadableBytes() {
        return BIO_pending(mWriterBio);
    }

    void read(ByteBuf &byteBuf) {
        char buff[4096];
        while (true) {
            auto bytes = BIO_pending(mWriterBio);
            if (bytes <= 0) {
                break;
            }
            bytes = BIO_read(mWriterBio, buff, sizeof(buff));
            if (bytes <= 0) {
                break;
            }
            byteBuf.writeBytes(buff, bytes);
        }
    }

    void write(ByteBuf &byteBuf) {
        auto ret = BIO_write(mReaderBio, byteBuf.readData(), byteBuf.readableBytes());
        if (ret > 0) {
            byteBuf.readIndex(byteBuf.readIndex() + ret);
        }
    }

    void shutdown() {
        SSL_shutdown(mSSL);
    }

    void setHost(const std::string_view &host) {
        mHost = host;
        SSL_set1_host(mSSL, mHost.c_str());
        SSL_set_tlsext_host_name(mSSL, mHost.c_str());
    }

    TLSMode mode() const { return mMode; }

    [[nodiscard]]
    bool isClientMode() const { return mMode == TLSMode::S2N_CLIENT; }
};

class TLSContextFactory: public std::enable_shared_from_this<TLSContextFactory> {
    friend class TLSContext;

    SSL_CTX *mSSLCtx = nullptr;

    static int sslError(int ret) {
        if (ret == 1) {
            return 0;
        }
        return -1;
    }

public:
    struct GlobalInit {
        explicit GlobalInit() {
            SSL_library_init();
            SSL_load_error_strings();
        }
    };

    explicit TLSContextFactory() {
        static GlobalInit initLibrary;
        mSSLCtx = SSL_CTX_new(TLS_method());
        auto ret = SSL_CTX_set_min_proto_version(mSSLCtx, TLS1_2_VERSION);
        CHECK(ret == 1, "SSL_CTX_set_min_proto_version() == %ld", ret)

        ret = SSL_CTX_set_max_proto_version(mSSLCtx, TLS1_3_VERSION);
        CHECK(ret == 1, "SSL_CTX_set_max_proto_version() = %ld", ret)

        ret = SSL_CTX_set_cipher_list(mSSLCtx, "HIGH:!aNULL:!MD5");
        CHECK(ret == 1, "SSL_CTX_set_cipher_list() = %ld", ret)

        ret = SSL_CTX_set_default_verify_paths(mSSLCtx);
        CHECK(ret == 1, "SSL_CTX_set_default_verify_paths() = %ld", ret)
    }

    NO_COPY(TLSContextFactory)

    ~TLSContextFactory() {
        SSL_CTX_free(mSSLCtx);
        mSSLCtx = nullptr;
    }

    int certFile(const std::string_view &certFile, const std::string_view &keyFile) {
        std::string cert(certFile);
        std::string key(keyFile);
        auto ret = SSL_CTX_use_certificate_chain_file(mSSLCtx, cert.c_str());
        if (ret != 1) { return sslError(ret); }

        ret = SSL_CTX_use_PrivateKey_file(mSSLCtx, key.c_str(), SSL_FILETYPE_PEM);
        if (ret != 1) { return sslError(ret); }

        ret = SSL_CTX_check_private_key(mSSLCtx);
        return sslError(ret);
    }

    TLSContextPtr newInstance(TLSMode mode) {
        return std::make_shared<TLSContext>(SSL_new(mSSLCtx), mode);
    }
};


class TLSContextHandler: public ChannelDuplexHandler {

    ByteBuf mTmpWriteBuff;
    TLSContextPtr mTLSContext;

    enum State {
        INIT,
        HANDSHAKE,
        OK,
        ERROR,
    };

    State mState = State::INIT;

    void decode(ChannelHandlerContext &ctx) {
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
        flush(ctx);
    }

    void onInit(ChannelHandlerContext &ctx) {
        // client 必须设置 sni
        if (mTLSContext->isClientMode()) {
            auto &host = ctx.channel().connectHost();
            if (!host.empty()) {
                LOGW("rewrite sni from channel connect name: '%s'", host.c_str());
                mTLSContext->setHost(host);
            } else {
                LOGW("empty sni, will not rewrite from channel");
            }
        }
        mState = State::HANDSHAKE;
    }

    void onHandshake(ChannelHandlerContext &) {
        switch (mTLSContext->handshake()) {
            case TLSContext::AGAIN: {
                break;
            }
            case TLSContext::OK: {
                mTLSContext->send(mTmpWriteBuff);
                mTmpWriteBuff.release();
                mState = State::OK;
                break;
            }
            case TLSContext::ERROR: {
                LOGW("TLS handshake failed");
                mState = State::ERROR;
                break;
            }
        }
    }

    void onOk(ChannelHandlerContext &ctx) {
        while (true) {
            auto msg = makeAny<ByteBuf>(16 * 1024);
            auto byteBuf = msg->as<ByteBuf>();
            mTLSContext->recv(*byteBuf);
            if (byteBuf->readableBytes() == 0) {
                break;
            }
            ctx.fireChannelRead(std::move(msg));
        }
    }

    void onError(ChannelHandlerContext &ctx) {
        mTLSContext->shutdown();
        mTmpWriteBuff.release();
        ctx.close();
    }

    void encode(ChannelHandlerContext &, ByteBuf &byteBuf, const PromisePtr<void>& promise) {
        bool ok = true;
        if (mState == State::HANDSHAKE) {
            mTmpWriteBuff.cumulate(byteBuf);
        }
        if (mState == State::OK) {
            mTLSContext->send(byteBuf);
        }
        if (mState == State::ERROR) {
            ok = false;
        }
        if (promise) {
            if (ok) {
                promise->setSuccess();
            } else {
                promise->setFailure();
            }
        }
    }

public:
    void handlerAdded(ChannelHandlerContext &ctx) override {
        if (mTLSContext->isClientMode() && ctx.channel().isActive()) {
            decode(ctx);
        }
    }

    void channelActive(hysburg::ChannelHandlerContext &ctx) override {
        if (mTLSContext->isClientMode()) {
            decode(ctx);
        }
        ctx.fireChannelActive();
    }

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) override {
        if (!msg->is<ByteBuf>()) {
            ctx.fireChannelRead(std::move(msg));
            return;
        }
        mTLSContext->write(*msg->as<ByteBuf>());
        decode(ctx);
    }

    void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) override {
        if (!msg->is<ByteBuf>()) {
            ctx.write(std::move(msg), std::move(promise));
            return;
        }
        encode(ctx, *msg->as<ByteBuf>(), promise);
    }

    void flush(ChannelHandlerContext &ctx) override {
        if (mTLSContext->pendingReadableBytes() <= 0) {
            return;
        }
        auto msg = makeAny<ByteBuf>(16 * 1024);
        auto byteBuf = msg->as<ByteBuf>();
        mTLSContext->read(*byteBuf);
        if (byteBuf->readableBytes() > 0) {
            ctx.writeAndFlush(std::move(msg));
        }
    }

    void close(ChannelHandlerContext &ctx) override {
        if (mState != State::ERROR) {
            mTLSContext->shutdown();
        }
        ctx.close();
    }

    explicit TLSContextHandler(TLSContextPtr tlsCtx) {
        mTLSContext.swap(tlsCtx);
    }

    explicit TLSContextHandler(TLSContextFactoryPtr &factory, TLSMode mode):
            TLSContextHandler(factory->newInstance(mode)) {
    }

    NO_COPY(TLSContextHandler)

    [[nodiscard]]
    TLSContextPtr tlsContext() { return mTLSContext; }
};

}

#endif // HYSBURG_TLS_CONTEXT
