
//#include "channel/Future.hpp"
#include "channel/UVSocketChannel.hpp"
#include "channel/ChannelHandler.hpp"
#include "channel/HttpObject.hpp"

using namespace hysburg;

struct EchoHandler: public ChannelHandler {

    void handlerAdded(ChannelHandlerContext &ctx) noexcept override {
        LOGI("handlerAdded: ");
    }

    void handlerRemoved(ChannelHandlerContext &ctx) noexcept override {
        LOGI("handlerRemoved: ");
    }

    void channelActive(ChannelHandlerContext &ctx) noexcept override {
        LOGI("channelActive: %s", ctx.channel().remoteAddrString().c_str());
//        auto msg = makeAny<ByteBuf>();
//        auto byteBuf = msg->as<ByteBuf>();
//
//        byteBuf->writeBytes("GET / HTTP/1.1\r\n");
//        byteBuf->writeBytes("Connection: close\r\n");
//        byteBuf->writeBytes("Host: www.baidu.com\r\n");
//        byteBuf->writeBytes("User-Agent: okhttp3\r\n");
//        byteBuf->writeBytes("\r\n");
//
//        ctx.writeAndFlush(std::move(msg));
    }

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override {
        LOGI("channelRead: %s", ctx.channel().remoteAddrString().c_str());
        auto byteBuf = msg->as<ByteBuf>();
        Log::print((char*) byteBuf->readData(), byteBuf->readableBytes());
        ctx.writeAndFlush(std::move(msg));
    }

    void userEventTriggered(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override {
        LOGI("userEventTriggered: ");
    }

    void channelInactive(ChannelHandlerContext &ctx) noexcept override {
        LOGI("channelInactive: %s", ctx.channel().remoteAddrString().c_str());
    }

    void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) noexcept override {
        ctx.write(std::move(msg), std::move(promise));
    }

    void flush(ChannelHandlerContext &ctx) noexcept override {
        ctx.flush();
    }

    void close(ChannelHandlerContext &ctx) noexcept override {
        ctx.close();
    }

    EchoHandler(): ChannelHandler(ChannelHandler::FLAG_INBOUNDS|ChannelHandler::FLAG_OUTBOUNDS) {
    }

    ~EchoHandler() noexcept override {
        LOGD("~EchoHandler()");
    }
};

struct HttpEchoHandler: public SimpleInboundChannelHandler<HttpRequest> {

    void channelRead0(ChannelHandlerContext &ctx, HttpRequest &msg) noexcept override {
        if (!msg.isSuccess) {
            LOGI("invalid http request, close it '%s'", ctx.channel().remoteAddrString().c_str());
            ctx.close();
            return;
        }
        auto respMsg = makeAny<HttpResponse>();
        auto response = respMsg->as<HttpResponse>();
        response->headers = {
                { "content-type", "text" }
        };
        auto &body = response->body;
        body.append(msg.method).append(" ")
            .append(msg.path).append(" ")
            .append("HTTP/1.1\r\n");
        for (auto &it : msg.headers) {
            body.append(it.first)
                .append(": ")
                .append(it.second)
                .append("\r\n");
        }
        body.append("\r\n");
        body.append(msg.body);

        ctx.writeAndFlush(std::move(respMsg));
    }

    void channelActive(hysburg::ChannelHandlerContext &ctx) noexcept override {
        LOGI("channelActive: %s", ctx.channel().remoteAddrString().c_str());
        ctx.fireChannelActive();
    }

    void channelInactive(hysburg::ChannelHandlerContext &ctx) noexcept override {
        LOGI("channelInactive: %s", ctx.channel().remoteAddrString().c_str());
        ctx.fireChannelInactive();
    }
};

int main() {
    auto group = std::make_shared<EventLoopGroup>(2);
//    Channel *channel = nullptr;
//
//    Bootstrap()
//        .eventLoop(eventLoop)
//        .channel(&channel)
//        .handler(std::make_shared<EchoHandler>())
//        .connect("baidu.com", 80)
//        ->addListener(channel->closeOnFailure());
//
//    eventLoop->loop();

    Channel *channel; {
        ServerBootstrap<UVServerSocketChannel> b;
        b.eventLoopGroup(group)
                .channel(&channel)
                .emplaceChildHandler<ChannelInitializer>([](Channel &channel) {
                    channel.pipeline()
                        .addLast("HttpClientCodec", std::make_shared<HttpServerCodec>())
                        .addLast("HttpEchoHandler", std::make_shared<HttpEchoHandler>());
                });
        b.bind("127.0.0.1", 8080)->sync();
        b.listen(64)->sync();
    }
    while (true) {
        sleep(1000);
    }
    return 0;
}