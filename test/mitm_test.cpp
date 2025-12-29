


#include "channel/UVSocketChannel.hpp"
#include "channel/ChannelHandler.hpp"
#include "channel/TLSContext.hpp"

using namespace hysburg;


struct RelayHandler: ChannelInboundHandler {
    ChannelHandlerContext *thisCtx = nullptr;
    ChannelHandlerContext *otherCtx = nullptr;
    TLSContext *tlsContext = nullptr;
    ByteBuf tmpInputBuf;

    std::function<void()> onFakeCertReady;

    void channelActive(ChannelHandlerContext &ctx) noexcept override {
        ctx.fireChannelActive();

        thisCtx = &ctx;
        if (tmpInputBuf.readableBytes() > 0) {
            AnyPtr any;
            auto tmp = makeAnyIn<ByteBuf>(any);
            tmp->swap(tmpInputBuf);
            ctx.writeAndFlush(std::move(any));
        }
    }

    void channelRead(ChannelHandlerContext &, AnyPtr msg) noexcept override {
        if (otherCtx != nullptr) {
            otherCtx->writeAndFlush(std::move(msg));
        }
    }

    void channelInactive(ChannelHandlerContext &ctx) noexcept override {
        ctx.fireChannelInactive();
        thisCtx = nullptr;
        if (otherCtx != nullptr) {
            otherCtx->close();
        }
        otherCtx = nullptr;
        onFakeCertReady = nullptr;
        tlsContext = nullptr;
    }

    void userEventTriggered(ChannelHandlerContext &ctx, AnyPtr msg) override {
        auto event = msg->is<TLSHandshakeEvent>();
        if (event != nullptr && tlsContext != nullptr && *event == TLS_HANDSHAKE_OK) {
            if (onFakeCertReady != nullptr) {
                onFakeCertReady();
            }
        }
        ctx.fireUserEvent(std::move(msg));
    }

    void send(AnyPtr msg) {
        auto byteBuf = msg->is<ByteBuf>();
        if (byteBuf == nullptr) {
            return;
        }
        if (thisCtx == nullptr) {
            tmpInputBuf.cumulate(*byteBuf);
            return;
        }
        thisCtx->writeAndFlush(std::move(msg));
    }
};

struct MyHandler: ChannelInboundHandler {

    TLSContextPtr mTLSContext;
    std::shared_ptr<RelayHandler> relayHandler;

    enum Status {
        INIT,
        PENDING,
        READY,
    };
    Status mStatus = Status::INIT;

    void channelActive(ChannelHandlerContext &ctx) override {
        ctx.fireChannelActive();
        mTLSContext->setClientHelloCallback([this, &ctx]() -> int {
            LOGI("on client hello");
            switch (mStatus) {
                case Status::INIT:
                    startConnect(ctx);
                    mStatus = Status::PENDING;
                case PENDING:
                    return SSL_CLIENT_HELLO_RETRY;
                case READY:
                    return SSL_CLIENT_HELLO_SUCCESS;
            }
        });
    }

    void channelRead(hysburg::ChannelHandlerContext &, hysburg::AnyPtr msg) override {
        if (relayHandler != nullptr) {
            relayHandler->send(std::move(msg));
        }
    }

    void startConnect(ChannelHandlerContext &ctx) {
        auto tlsContext = mTLSContext->factory()->newInstance(TLSMode::TLS_CLIENT);
        relayHandler = std::make_shared<RelayHandler>();
        relayHandler->otherCtx = &ctx;
        relayHandler->tlsContext = tlsContext.get();
        relayHandler->onFakeCertReady = [this, &ctx]() {
            auto pair = makeFakeCert();
            assert(mTLSContext->setCert(*pair.first, *pair.second));
            mStatus = READY;
            // 重新触发一次握手
            ctx.channel().pipeline().fireChannelRead(makeAny<ByteBuf>());
        };

        Bootstrap<UVSocketChannel>()
                .eventLoop(ctx.channel().executor())
                .emplaceHandler<TLSContextHandler>(tlsContext)
                .handler(relayHandler)
                .connect("127.0.0.1", 443);
    }

    std::pair<X509CertificatePtr, EvpKeyPtr> makeFakeCert() {
        auto ca_cert = X509Certificate::fromFile("/tmp/ca/myCA.crt");
        auto ca_key = EvpKey::fromPrivateKey("/tmp/ca/myCA.key");

        assert(ca_cert->matches(ca_key));

        auto real_cert = relayHandler->tlsContext->peerCertificate();
        auto fake_pkey = EvpKey::fromRSA(2048);
        auto fake_x509 = makeFakeCert(
                *real_cert, *ca_cert, *ca_key, *fake_pkey
        );
        return { fake_x509, fake_pkey };
    }

    X509CertificatePtr makeFakeCert(
            X509Certificate &original_cert,
            X509Certificate &ca_cert,
            EvpKey &ca_key,
            EvpKey &fake_pkey
    ) {
        auto fake_x509 = std::make_shared<X509Certificate>();

        // 设置序列号 (Serial Number)
        auto serial = fake_x509->serialNumber();
        std::unique_ptr<BIGNUM, decltype(&BN_free)> bn_serial(BN_new(), BN_free);
        BN_rand(bn_serial.get(), 64, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
        BN_to_ASN1_INTEGER(bn_serial.get(), serial);

        // 复制有效期 (NotBefore 和 NotAfter)
        fake_x509->setNotBefore(original_cert.notBefore());
        fake_x509->setNotAfter(original_cert.notAfter());

        // 复制 Subject Name (这是 Common Name 所在的地方)
        fake_x509->setSubjectName(original_cert.subjectName());

        // 设置 Issuer Name (颁发者必须是我们的 CA)
        fake_x509->setIssuerName(ca_cert.subjectName());

        // 设置公钥
        fake_x509->setPubKey(fake_pkey);

        // 处理扩展 (Extensions) —— 核心部分
        auto san = original_cert.getExt(NID_subject_alt_name, -1);
        if (san != nullptr) {
            fake_x509->addExt(san, -1);
        }

        // 添加 Basic Constraints (表明这不是一个 CA)
        {
            std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
                    X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints, "CA:FALSE"),
                    X509_EXTENSION_free
            );
            fake_x509->addExt(ext.get());
        }
        // 添加 Key Usage
        {
            std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
                    X509V3_EXT_conf_nid(nullptr, nullptr, NID_key_usage, "digitalSignature, keyEncipherment"),
                    X509_EXTENSION_free
            );
            fake_x509->addExt(ext.get());
        }
        auto ok = fake_x509->sign(ca_key, EVP_sha256());
        assert(ok);
        return fake_x509;
    }

    void channelInactive(ChannelHandlerContext &ctx) noexcept override {
        ctx.fireChannelInactive();

        if (relayHandler != nullptr) {
            relayHandler->otherCtx = nullptr;
            if (relayHandler->thisCtx != nullptr) {
                relayHandler->thisCtx->close();
            }
            relayHandler = nullptr;
        }
    }
};


int main() {
    auto eventLoop = std::make_shared<EventLoop>();
    TLSContextFactory factory;

    ServerBootstrap<UVServerSocketChannel> b;
    b.eventLoop(eventLoop)
            .childHandler<ChannelInitializer>([&](Channel &channel) {
                auto tls = factory.newInstance(TLSMode::TLS_SERVER);
                auto my = std::make_shared<MyHandler>();
                my->mTLSContext = tls;

                channel.pipeline()
                        .addLast(std::make_shared<TLSContextHandler>(tls))
                        .addLast("MyHandler", my)
                        ;
            })
            .bind("127.0.0.1",  8443);
    LOGI("bind success");
    b.listen(64);

    eventLoop->loop();
    return 0;
}