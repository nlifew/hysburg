

#include "channel/UVSocketChannel.hpp"
#include "channel/ChannelHandler.hpp"
#include "channel/Socks5.hpp"

using namespace hysburg;

struct Socks5InitRequestHandler: SimpleInboundChannelHandler<Socks5InitialRequest> {

    void channelActive(hysburg::ChannelHandlerContext &ctx) noexcept override {
        ctx.fireChannelActive();
        ctx.channel().option(ChannelOption::NO_DELAY, 1);
    }

    void channelRead0(ChannelHandlerContext &ctx, Socks5InitialRequest &msg) noexcept override {
        LOGD("Socks5InitRequestHandler: read !");
        if (!msg.success) {
            ctx.close();
            return;
        }
        AnyPtr any = makeAny<Socks5InitialResponse>();
        ctx.writeAndFlush(std::move(any));
    }
};


struct ConnectAddress {
    std::string addr;
    int port = 0;
};

struct Socks5CommandRequestHandler: SimpleInboundChannelHandler<Socks5CommandRequest> {


    void channelRead0(ChannelHandlerContext &ctx, Socks5CommandRequest &msg) noexcept override {
        LOGD("Socks5CommandRequestHandler: read !");
        if (!msg.success) {
            ctx.close();
            return;
        }
        if (msg.cmd != Socks5Command::CONNECT) {
            AnyPtr any;
            auto resp = makeAnyIn<Socks5CommandResponse>(any);
            resp->reply = Socks5Reply::COMMAND_NOT_SUPPORTED;
            ctx.writeAndFlush(std::move(any));
            return;
        }

        LOGI("socks5 client '%s' try to connect '%s'",
             ctx.channel().remoteAddrString().c_str(),
             msg.toString().c_str()
        );
        AnyPtr any;
        auto bean = makeAnyIn<ConnectAddress>(any);
        bean->addr = msg.addrToString();
        bean->port = msg.port;
        ctx.fireChannelRead(std::move(any));
    }
};


struct RelayHandler: ChannelInboundHandler {
    ChannelHandlerContext *thisCtx = nullptr;
    ChannelHandlerContext *otherCtx = nullptr;
    ByteBuf tmpInputBuf;

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

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override {
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

    std::shared_ptr<RelayHandler> relayHandler;
    FuturePtr<void> connectFuture;
    int connectListenerId = -1;

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override {
        if (msg->is<ConnectAddress>()) {
            auto tmp = msg->as<ConnectAddress>();
            startConnect(ctx, tmp->addr, tmp->port);
        }
        if (msg->is<ByteBuf>() && relayHandler != nullptr) {
            relayHandler->send(std::move(msg));
        }
    }

    void startConnect(ChannelHandlerContext &ctx, const std::string_view &addr, int port) {
        relayHandler = std::make_shared<RelayHandler>();
        relayHandler->otherCtx = &ctx;

        connectFuture = Bootstrap<UVSocketChannel>()
                .eventLoop(ctx.channel().executor())
                .handler(relayHandler)
                .connect(addr, port);

        connectListenerId = connectFuture->addListener([this, &ctx](auto &future) {
            LOGI("socks5 client '%s' connect result: '%s'",
                 ctx.channel().remoteAddrString().c_str(),
                 future.isSuccess() ? "ok" : "failed"
            );
            connectListenerId = -1;
            connectFuture = nullptr;
            if (!future.isSuccess()) {
                writeReply(ctx, Socks5Reply::HOST_UNREACHABLE);
                return;
            }
            writeReply(ctx, Socks5Reply::SUCCESS);
        });
    }

    void writeReply(ChannelHandlerContext &ctx, Socks5Reply reply) {
        AnyPtr any;
        auto resp = makeAnyIn<Socks5CommandResponse>(any);
        resp->reply = reply;
        ctx.writeAndFlush(std::move(any));
    }

    void channelInactive(ChannelHandlerContext &ctx) noexcept override {
        ctx.fireChannelInactive();

        if (connectListenerId > 0 && connectFuture != nullptr) {
            connectFuture->removeListener(connectListenerId);
            connectListenerId = -1;
        }
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
    auto group = std::make_shared<EventLoopGroup>(4);

    ServerBootstrap<UVServerSocketChannel> b;
    b.eventLoop(group)
            .childHandler<ChannelInitializer>([](Channel &channel) {
                channel.pipeline()
                        .addLast("Socks5Encoder", std::make_shared<Socks5MsgEncoder>())
                        .addLast("Socks5InitDecoder", std::make_shared<Socks5InitRequestDecoder>())
                        .addLast("Socks5InitHandler", std::make_shared<Socks5InitRequestHandler>())
                        .addLast("Socks5CommandDecoder", std::make_shared<Socks5CommandRequestDecoder>())
                        .addLast("Socks5CommandHandler", std::make_shared<Socks5CommandRequestHandler>())
                        .addLast("MyHandler", std::make_shared<MyHandler>())
                        ;
            })
            .bind("127.0.0.1",  8080)->sync();
    LOGI("bind success");

    b.listen(64)->sync();

    while (true) {
        uv_sleep(1000);
    }
    return 0;
}