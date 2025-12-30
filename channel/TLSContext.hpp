

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

class X509Certificate;
using X509CertificatePtr = std::shared_ptr<X509Certificate>;

class EvpKey;
using EvpKeyPtr = std::shared_ptr<EvpKey>;


class EvpKey {
    friend class X509Certificate;
    friend class TLSContext;

    EVP_PKEY *mKey;

    template<typename T>
    static EvpKeyPtr fromFile(const char *path, T obj) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
                BIO_new(BIO_s_file()), BIO_free
        );
        auto ret = BIO_read_filename(bio.get(), path);
        if (ret != 1) {
            return nullptr;
        }
        auto key = obj(bio.get(), nullptr, nullptr, nullptr);
        if (key == nullptr) {
            return nullptr;
        }
        return std::make_shared<EvpKey>(key);
    }

public:
    static EvpKeyPtr fromPublicKey(const char *path) {
        return fromFile(path, PEM_read_bio_PUBKEY);
    }

    static EvpKeyPtr fromPrivateKey(const char *path) {
        return fromFile(path, PEM_read_bio_PrivateKey);
    }

    static EvpKeyPtr fromRSA(int bitCount) {
        auto key = std::make_shared<EvpKey>();
        std::unique_ptr<BIGNUM, decltype(&BN_free)> bne(BN_new(), BN_free);
        std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);

        BN_set_word(bne.get(), RSA_F4);
        RSA_generate_key_ex(rsa.get(), bitCount, bne.get(), nullptr);
        EVP_PKEY_assign_RSA(key->mKey, rsa.release()); // rsa 已经被 assign 管理，不需要释放 RSA，但 bne 需要释放
        return key;
    }

    explicit EvpKey(EVP_PKEY *key): mKey(key) {
    }

    EvpKey() {
        mKey = EVP_PKEY_new();
    }

    ~EvpKey() {
        EVP_PKEY_free(mKey);
    }
    NO_COPY(EvpKey)
};

class X509Certificate {
    friend class TLSContext;
    X509 *mX509 = nullptr;
public:
    static X509CertificatePtr fromFile(const char *path) {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(
                BIO_new(BIO_s_file()), BIO_free
        );
        auto ret = BIO_read_filename(bio.get(), path);
        if (ret != 1) {
            return nullptr;
        }
        auto cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (cert == nullptr) {
            return nullptr;
        }
        return std::make_shared<X509Certificate>(cert);
    }

    explicit X509Certificate() {
        mX509 = X509_new();
        X509_set_version(mX509, 2);
    }

    explicit X509Certificate(X509 *x509) :mX509(x509) {
    }

    ~X509Certificate() {
        X509_free(mX509);
    }

    NO_COPY(X509Certificate)

    X509_NAME *subjectName() { return X509_get_subject_name(mX509); }
    void setSubjectName(X509_NAME *name) { X509_set_subject_name(mX509, name); }

    const ASN1_TIME *notBefore() { return X509_get0_notBefore(mX509); }
    const ASN1_TIME *notAfter() { return X509_get0_notAfter(mX509); }

    void setNotBefore(const ASN1_TIME *time) { X509_set1_notBefore(mX509, time); }
    void setNotAfter(const ASN1_TIME *time) { X509_set1_notAfter(mX509, time); }

    ASN1_INTEGER *serialNumber() { return X509_get_serialNumber(mX509); }

    X509_NAME *issuerName() { return X509_get_issuer_name(mX509); }
    void setIssuerName(X509_NAME *name) { X509_set_issuer_name(mX509, name); }

    void setPubKey(EvpKey &key) { X509_set_pubkey(mX509, key.mKey); }

    void addExt(X509_EXTENSION *ext, int index = -1) { X509_add_ext(mX509, ext, index); }

    X509_EXTENSION *getExt(int nid, int lastPos = -1) {
        auto idx = X509_get_ext_by_NID(mX509, nid, lastPos);
        if (idx < 0) {
            return nullptr;
        }
        return X509_get_ext(mX509, idx);
    }

    bool sign(EvpKey &caKey, const EVP_MD *md) {
        auto ret = X509_sign(mX509, caKey.mKey, md);
        return ret > 0; // 所有函数成功时返回签名大小（以字节为单位），失败时返回 0
    }

    bool matches(EvpKey &key) {
        auto ret = X509_check_private_key(mX509, key.mKey);
        return ret == 1;
    }

    bool matches(const EvpKeyPtr &key) {
        return matches(*key.get());
    }
};

enum TLSMode {
    TLS_SERVER,
    TLS_CLIENT,
};


class TLSContext: std::enable_shared_from_this<TLSContext> {
public:
    static constexpr int CLIENT_HELLO_SUCCESS = ssl_select_cert_result_t::ssl_select_cert_success;
    static constexpr int CLIENT_HELLO_RETRY = ssl_select_cert_result_t::ssl_select_cert_retry;
    static constexpr int CLIENT_HELLO_ERROR = ssl_select_cert_result_t::ssl_select_cert_error;
    using ClientHelloCallback = std::function<int()>;

private:
    friend class TLSContextFactory;

    SSL *mSSL = nullptr;
    BIO *mReaderBio = nullptr;
    BIO *mWriterBio = nullptr;
    TLSMode mMode = TLSMode::TLS_CLIENT;

    /**
     * 低版本中 SSL_set_tlsext_host_name() 似乎不会执行 strdup() 而是直接使用
     * 开发者传进去的指针，但不是很确定。此处保险起见放一个 std::string
     */
    std::string mSni;
    ClientHelloCallback mClientHelloCallback;

    ssl_select_cert_result_t dispatchClientHello(const SSL_CLIENT_HELLO *) {
        auto ret = ssl_select_cert_success;
        if (mClientHelloCallback != nullptr) {
            ret = static_cast<ssl_select_cert_result_t>(mClientHelloCallback());
        }
        return ret;
    }

    // 只能通过 factory 访问，不支持直接构造
    explicit TLSContext(SSL *ssl, TLSMode mode) {
        mSSL = ssl;
        mMode = mode;
        mReaderBio = BIO_new(BIO_s_mem());
        mWriterBio = BIO_new(BIO_s_mem());

        SSL_set0_rbio(mSSL, mReaderBio);
        SSL_set0_wbio(mSSL, mWriterBio);

        if (mode == TLSMode::TLS_CLIENT) {
            SSL_set_connect_state(mSSL);
            SSL_set_verify(mSSL, SSL_VERIFY_PEER, nullptr);
        } else {
            SSL_set_accept_state(mSSL);
        }
        SSL_set_app_data(mSSL, this);
    }

public:
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
        switch (ret = SSL_get_error(mSSL, ret)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_PENDING_CERTIFICATE:
                return HandshakeResult::AGAIN;
        }
        std::string stacktrace;

        unsigned long e;
        while ((e = ERR_get_error()) != 0) {
            char buf[256] = { 0 };
            ERR_error_string_n(e, buf, sizeof(buf));
            stacktrace += buf;
            stacktrace += "\n";
        }
        LOGE("ssl handshake failed: %d\n%s", ret, stacktrace.c_str());
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

    void read(ByteBuf &byteBuf) {
        char buff[4096];
        while (true) {
            auto bytes = BIO_read(mWriterBio, buff, sizeof(buff));
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

    void setSni(const std::string_view &sni) {
        mSni = sni;
        SSL_set1_host(mSSL, mSni.c_str());
        SSL_set_tlsext_host_name(mSSL, mSni.c_str());
    }

    const char *sni() {
        auto it = SSL_get_servername(mSSL, TLSEXT_NAMETYPE_host_name);
        return it ? it : "";
    }

    [[nodiscard]]
    TLSMode mode() const { return mMode; }

    [[nodiscard]]
    X509CertificatePtr peerCertificate() {
        auto x509 = SSL_get_peer_certificate(mSSL);
        return std::make_shared<X509Certificate>(x509);
    }

    void setClientHelloCallback(ClientHelloCallback cb) { mClientHelloCallback.swap(cb); }

    bool setCert(X509Certificate &cert, EvpKey &key) {
        if (auto ret = SSL_use_certificate(mSSL, cert.mX509); ret != 1) {
            return false;
        }
        if (auto ret = SSL_use_PrivateKey(mSSL, key.mKey); ret != 1) {
            return false;
        }
        if (auto ret = SSL_check_private_key(mSSL); ret != 1) {
            return false;
        }
//        auto ret = SSL_use_cert_and_key(mSSL, cert.handle(), key.handle(), nullptr, 1);
        return true;
    }

    TLSContextFactory *factory();
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
    explicit TLSContextFactory() {
        mSSLCtx = SSL_CTX_new(TLS_method());
        long int ret = SSL_CTX_set_min_proto_version(mSSLCtx, TLS1_2_VERSION);
        CHECK(ret == 1, "SSL_CTX_set_min_proto_version() == %ld", ret)

        ret = SSL_CTX_set_max_proto_version(mSSLCtx, TLS1_3_VERSION);
        CHECK(ret == 1, "SSL_CTX_set_max_proto_version() = %ld", ret)

        ret = SSL_CTX_set_cipher_list(mSSLCtx, "HIGH:!aNULL:!MD5");
        CHECK(ret == 1, "SSL_CTX_set_cipher_list() = %ld", ret)

        ret = SSL_CTX_set_default_verify_paths(mSSLCtx);
        CHECK(ret == 1, "SSL_CTX_set_default_verify_paths() = %ld", ret)

        // 启用 grease
        SSL_CTX_set_grease_enabled(mSSLCtx, 1);

        SSL_CTX_set_app_data(mSSLCtx, this);
        SSL_CTX_set_select_certificate_cb(
                mSSLCtx,
                +[](const SSL_CLIENT_HELLO *sch) -> ssl_select_cert_result_t {
                    auto self = static_cast<TLSContext*>(SSL_get_app_data(sch->ssl));
                    return self->dispatchClientHello(sch);
                }
        );
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

    int loadCAFile(const char *path) {
        auto ret = SSL_CTX_load_verify_locations(mSSLCtx, path, nullptr);
        return sslError(ret);
    }

    TLSContextPtr newInstance(TLSMode mode) {
        return TLSContextPtr(new TLSContext(SSL_new(mSSLCtx), mode));
    }

    SSL_CTX *handle() { return mSSLCtx; }
};


enum TLSHandshakeEvent {
    TLS_HANDSHAKE_START = 1,
    TLS_HANDSHAKE_OK = 2,
    TLS_HANDSHAKE_ERROR = 3,
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
        assert(mMyId == Log::threadId());
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
        if (mTLSContext->mode() == TLSMode::TLS_CLIENT) {
//            auto &host = ctx.channel().connectHost();
//            if (!host.empty()) {
//                LOGW("rewrite sni from channel connect name: '%s'", host.c_str());
//                mTLSContext->setSni(host);
//            } else {
//                LOGW("empty sni, will not rewrite from channel");
//            }
        }
        mState = State::HANDSHAKE;
        ctx.fireUserEvent(makeAny<TLSHandshakeEvent>(TLS_HANDSHAKE_START));
    }

    void onHandshake(ChannelHandlerContext &ctx) {
        switch (mTLSContext->handshake()) {
            case TLSContext::AGAIN: {
                break;
            }
            case TLSContext::OK: {
                mTLSContext->send(mTmpWriteBuff);
                mTmpWriteBuff.release();
                mState = State::OK;
                ctx.fireUserEvent(makeAny<TLSHandshakeEvent>(TLS_HANDSHAKE_OK));
                break;
            }
            case TLSContext::ERROR: {
                LOGW("TLS handshake failed");
                mState = State::ERROR;
                ctx.fireUserEvent(makeAny<TLSHandshakeEvent>(TLS_HANDSHAKE_ERROR));
                break;
            }
        }
    }

    void onOk(ChannelHandlerContext &ctx) {
        while (true) {
            auto msg = makeAny<ByteBuf>();
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
        assert(mMyId == Log::threadId());
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

    uint64_t mMyId = Log::threadId();

public:
    void handlerAdded(ChannelHandlerContext &ctx) override {
        assert(mMyId == Log::threadId());
        if (mTLSContext->mode() == TLSMode::TLS_CLIENT && ctx.channel().isActive()) {
            decode(ctx);
        }
    }

    void channelActive(hysburg::ChannelHandlerContext &ctx) override {
        assert(mMyId == Log::threadId());
        if (mTLSContext->mode() == TLSMode::TLS_CLIENT) {
            decode(ctx);
        }
        ctx.fireChannelActive();
    }

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) override {
        assert(mMyId == Log::threadId());
        if (!msg->is<ByteBuf>()) {
            ctx.fireChannelRead(std::move(msg));
            return;
        }
        mTLSContext->write(*msg->as<ByteBuf>());
        decode(ctx);
    }

    void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) override {
        assert(mMyId == Log::threadId());
        if (!msg->is<ByteBuf>()) {
            ctx.write(std::move(msg), std::move(promise));
            return;
        }
        encode(ctx, *msg->as<ByteBuf>(), promise);
    }

    void flush(ChannelHandlerContext &ctx) override {
        assert(mMyId == Log::threadId());
        auto msg = makeAny<ByteBuf>();
        auto byteBuf = msg->as<ByteBuf>();
        mTLSContext->read(*byteBuf);
        if (byteBuf->readableBytes() > 0) {
            ctx.writeAndFlush(std::move(msg));
        }
    }

    void close(ChannelHandlerContext &ctx) override {
        assert(mMyId == Log::threadId());
        if (mState != State::ERROR) {
            mTLSContext->shutdown();
        }
        ctx.close();
    }

    explicit TLSContextHandler(TLSContextPtr tlsCtx) {
        mTLSContext.swap(tlsCtx);
    }

    explicit TLSContextHandler(const TLSContextFactoryPtr &factory, TLSMode mode):
            TLSContextHandler(factory->newInstance(mode)) {
    }

    explicit TLSContextHandler(TLSContextFactory &factory, TLSMode mode):
            TLSContextHandler(factory.newInstance(mode)) {
    }

    NO_COPY(TLSContextHandler)

    [[nodiscard]]
    TLSContextPtr tlsContext() { return mTLSContext; }
};

}

#endif // HYSBURG_TLS_CONTEXT
