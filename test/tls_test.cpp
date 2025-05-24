
#include "channel/UVSocketChannel.hpp"
#include "channel/TLSContext.hpp"
#include "channel/ChannelHandler.hpp"

using namespace hysburg;

struct ClientHandler: public SimpleInboundChannelHandler<ByteBuf> {

    void channelActive(hysburg::ChannelHandlerContext &ctx) noexcept override {
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

    void channelRead0(ChannelHandlerContext &ctx, ByteBuf &msg) noexcept override {
        Log::print((char*) msg.readData(), msg.readableBytes());
        ctx.close();
    }
};


static void testClient() {
    auto executor = std::make_shared<EventLoop>();
    auto factory = std::make_shared<TLSContextFactory>();

    Channel *channel = nullptr;

    Bootstrap<UVSocketChannel>()
            .eventLoop(executor)
            .channel(&channel)
            .handler<ChannelInitializer>([&factory](Channel &channel) {
                channel.pipeline()
                        .emplaceLast<TLSContextHandler>(factory, TLSMode::S2N_CLIENT)
                        .emplaceLast<ClientHandler>();
            })
            .connect("www.baidu.com", 443);

    channel->closeFuture()->addListener([executor](auto &) {
        executor->quit();
    });

    executor->loop();
}

int main() {
    testClient();
    return 0;
}


