

#include "channel/Channel.hpp"

using namespace hysburg;


template<typename T>
PromisePtr<T> ChannelHandlerContext::newPromise() {
    return channel().newPromise<T>();
}

ChannelPipeline &ChannelHandlerContext::pipeline() const {
    return channel().pipeline();
}


void ChannelHandler::channelActive(ChannelHandlerContext &ctx) {
    ctx.fireChannelActive();
}

void ChannelHandler::channelRead(ChannelHandlerContext &ctx, AnyPtr msg) {
    ctx.fireChannelRead(std::move(msg));
}

void ChannelHandler::channelInactive(hysburg::ChannelHandlerContext &ctx) {
    ctx.fireChannelInactive();
}

void ChannelHandler::userEventTriggered(hysburg::ChannelHandlerContext &ctx, hysburg::AnyPtr msg) {
    ctx.fireUserEvent(std::move(msg));
}

void ChannelHandler::write(hysburg::ChannelHandlerContext &ctx, hysburg::AnyPtr msg, hysburg::PromisePtr<void> promise) {
    ctx.write(std::move(msg), std::move(promise));
}

void ChannelHandler::flush(hysburg::ChannelHandlerContext &ctx) {
    ctx.flush();
}

void ChannelHandler::close(hysburg::ChannelHandlerContext &ctx) {
    ctx.close();
}


namespace hysburg {

    struct HeadHandler: public ChannelHandler {
        void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) override {
            ctx.channel().doWrite(std::move(msg), std::move(promise));
        }

        void flush(ChannelHandlerContext &ctx) override {
            ctx.channel().doFlush();
        }

        void close(ChannelHandlerContext &ctx) override {
            ctx.channel().doClose();
        }
        explicit HeadHandler(): ChannelHandler(ChannelHandler::FLAG_OUTBOUNDS) {
        }
    };

    struct TailHandler: public ChannelHandler {
        explicit TailHandler(): ChannelHandler(0) {
        }
    };
}

void ChannelPipeline::initHeadAndTail() {
    doInsert(mTail, "HeadHandler", std::make_shared<HeadHandler>());
    doInsert(mTail, "TailHandler", std::make_shared<TailHandler>());
}
