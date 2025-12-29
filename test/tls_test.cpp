
#include "channel/UVSocketChannel.hpp"
#include "channel/TLSContext.hpp"
#include "channel/ChannelHandler.hpp"

using namespace hysburg;

struct ClientHandler: public SimpleInboundChannelHandler<ByteBuf> {

    void channelActive(hysburg::ChannelHandlerContext &ctx) override {
        ctx.fireChannelActive();
        auto msg = makeAny<ByteBuf>();
        auto byteBuf = msg->as<ByteBuf>();
        byteBuf->writeBytes("GET / HTTP/1.1\r\n");
        byteBuf->writeBytes("Host: www.baidu.com\r\n");
        byteBuf->writeBytes("User-Agent: okhttp3\r\n");
        byteBuf->writeBytes("Connection: close\r\n");
        byteBuf->writeBytes("\r\n");
        ctx.writeAndFlush(std::move(msg));
    }

    void channelRead0(ChannelHandlerContext &ctx, ByteBuf &msg) override {
        Log::print((char*) msg.readData(), msg.readableBytes());
        ctx.close();
    }
};

struct ServerHandler: SimpleInboundChannelHandler<ByteBuf> {
    void channelRead0(ChannelHandlerContext &ctx, ByteBuf &msg) override {
        auto resp = makeAny<ByteBuf>();
        auto byteBuf = resp->as<ByteBuf>();
        byteBuf->writeBytes("HTTP/1.1 200 OK\r\n");
        byteBuf->writeBytes("Content-Type: text/plain\r\n");
        byteBuf->writeBytes("Content-Length: " + std::to_string(msg.readableBytes()) + "\r\n");
        byteBuf->writeBytes("\r\n");
        byteBuf->cumulate(msg);
        ctx.writeAndFlush(std::move(resp));
    }
};

static void testClient() {
    auto executor = std::make_shared<EventLoop>();
    auto factory = std::make_shared<TLSContextFactory>();

    Channel *channel = nullptr;

    Bootstrap<UVSocketChannel>()
            .eventLoop(executor)
            .channel(&channel)
            .emplaceHandler<ChannelInitializer>([&factory](Channel &channel) {
                auto tlsContext = factory->newInstance(TLSMode::TLS_CLIENT);
                channel.pipeline()
                        .emplaceLast<TLSContextHandler>(std::move(tlsContext))
                        .emplaceLast<ClientHandler>();
            })
//            .connect("www.baidu.com", 443)
            .connect("localhost", 8443)
            ->addListener([](auto &future) {
                if (!future.isSuccess()) { abort(); }
            });

    channel->closeFuture()->addListener([executor](auto &) {
        exit(0);
    });

    executor->loop();
}

static void testServer() {
    auto executor = std::make_shared<EventLoop>();
    auto factory = std::make_shared<TLSContextFactory>();

    auto certFile = getenv("CERT_FILE");
    auto keyFile = getenv("KEY_FILE");

    CHECK(certFile, "CERT_FILE is empty. try to explicit by environment variable")
    CHECK(keyFile, "KEY_FILE is empty. try to explicit by environment variable")

    auto ret = factory->certFile(certFile, keyFile);
    CHECK(ret == 0, "factory->certFile() = %d", ret)

    Channel *channel = nullptr;
    ServerBootstrap<UVServerSocketChannel> server;
    server.eventLoop(executor)
        .channel(&channel)
        .childHandler<ChannelInitializer>([&factory](Channel &channel) {
            channel.pipeline()
                .emplaceLast<TLSContextHandler>(factory, TLSMode::TLS_SERVER)
                .emplaceLast<ServerHandler>();
        });

    server.bind("127.0.0.1", 8443)
        .get()->addListener(channel->closeOnFailure());
    server.listen(64)
        .get()->addListener(channel->closeOnFailure());

    channel->closeFuture()->addListener([&executor](auto &) {
        exit(0);
    });
    executor->loop();
}

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        return 1;
    }
    if (strcmp(argv[1], "server") == 0) {
        testServer();
    } else if (strcmp(argv[1], "client") == 0) {
        testClient();
    }
    return 0;
}


