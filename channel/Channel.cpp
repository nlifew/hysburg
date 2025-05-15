

#include "channel/Channel.hpp"

using namespace hysburg;


template<typename T>
PromisePtr<T> ChannelHandlerContext::newPromise() noexcept {
    return channel().newPromise<T>();
}

ChannelPipeline &ChannelHandlerContext::pipeline() const noexcept {
    return channel().pipeline();
}


void ChannelHandler::channelActive(ChannelHandlerContext &ctx) noexcept {
    ctx.fireChannelActive();
}

void ChannelHandler::channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept{
    ctx.fireChannelRead(std::move(msg));
}

void ChannelHandler::channelInactive(hysburg::ChannelHandlerContext &ctx) noexcept {
    ctx.fireChannelInactive();
}

void ChannelHandler::userEventTriggered(hysburg::ChannelHandlerContext &ctx, hysburg::AnyPtr msg) noexcept {
    ctx.fireUserEvent(std::move(msg));
}

void ChannelHandler::write(hysburg::ChannelHandlerContext &ctx, hysburg::AnyPtr msg, hysburg::PromisePtr<void> promise) noexcept {
    ctx.write(std::move(msg), std::move(promise));
}

void ChannelHandler::flush(hysburg::ChannelHandlerContext &ctx) noexcept {
    ctx.flush();
}

void ChannelHandler::close(hysburg::ChannelHandlerContext &ctx) noexcept {
    ctx.close();
}


namespace hysburg {

    struct HeadHandler: public ChannelHandler {
        void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) noexcept override {
            ctx.channel().doWrite(std::move(msg), std::move(promise));
        }

        void flush(ChannelHandlerContext &ctx) noexcept override {
            ctx.channel().doFlush();
        }

        void close(ChannelHandlerContext &ctx) noexcept override {
            ctx.channel().doClose();
        }
        explicit HeadHandler() noexcept: ChannelHandler(ChannelHandler::FLAG_OUTBOUNDS) {
        }
    };

    struct TailHandler: public ChannelHandler {
        explicit TailHandler() noexcept: ChannelHandler(0) {
        }
    };
}

void ChannelPipeline::initHeadAndTail() noexcept {
    doInsert(mTail, "HeadHandler", std::make_shared<HeadHandler>());
    doInsert(mTail, "TailHandler", std::make_shared<TailHandler>());
}
