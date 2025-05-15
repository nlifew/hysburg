
#ifndef HYSBURG_CHANNEL_HANDLER_HPP
#define HYSBURG_CHANNEL_HANDLER_HPP

#include <vector>
#include <type_traits>

#include "ByteBuf.hpp"
#include "Channel.hpp"
#include "Log.hpp"

namespace hysburg
{

struct ChannelInboundHandler : public ChannelHandler
{
    explicit ChannelInboundHandler() noexcept: ChannelHandler(ChannelHandler::FLAG_INBOUNDS) {
    }
};

struct ChannelOutboundHandler : public ChannelHandler
{
    explicit ChannelOutboundHandler() noexcept: ChannelHandler(ChannelHandler::FLAG_OUTBOUNDS) {
    }
};

struct ChannelDuplexHandler : public ChannelHandler
{
    static constexpr int FLAG = ChannelHandler::FLAG_INBOUNDS | ChannelHandler::FLAG_OUTBOUNDS;

    explicit ChannelDuplexHandler() noexcept: ChannelHandler(FLAG) {
    }
};


class ChannelInitializer: public ChannelInboundHandler
{
private:
    using FactoryType = std::function<void(Channel &)>;
    FactoryType mFactory;
protected:
    void handlerAdded(ChannelHandlerContext &ctx) noexcept override
    {
        if (mFactory != nullptr) {
            mFactory(ctx.channel());
//            mFactory = nullptr; // [1]
            // [1]. 事实上这个地方还不能删除，因为对于 ServerBootstrap，
            // childHandler 会在每个 channel 中调用，并不是只调用一次的。
            // 但这样也带来一个 *可能* 的内存泄漏问题，尤其是带捕获列表的 lambda 表达式。
            ctx.channel().pipeline().remove(this);
        }
    }

public:
    explicit ChannelInitializer(FactoryType factory) noexcept:
        mFactory(std::move(factory))
    {}

    NO_COPY(ChannelInitializer)
};


class ByteToMessageDecoder: public ChannelInboundHandler
{
private:
    ByteBuf mByteBuff;
    std::vector<AnyPtr> mOutList;
    bool mCallingDecode = false;

protected:
    virtual void decode(ChannelHandlerContext &ctx, ByteBuf &in, std::vector<AnyPtr> &out) noexcept = 0;

    virtual void callDecode(ChannelHandlerContext &ctx, ByteBuf &in, std::vector<AnyPtr> &out) noexcept {
        assert(!mCallingDecode);
        mCallingDecode = true;
        decode(ctx, in, out);
        mCallingDecode = false;
    }

    virtual void discardReadBytes(ByteBuf &in) noexcept {
        in.discardReadBytes();
    }

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override
    {
        if (!msg->is<ByteBuf>()) {
            ctx.fireChannelRead(std::move(msg));
            return;
        }
        mByteBuff.transferFrom(*msg->as<ByteBuf>());

        while (mByteBuff.readableBytes() > 0) {
            auto readIndex = mByteBuff.readIndex();
            callDecode(ctx, mByteBuff, mOutList);

            if (mOutList.empty()) {
                mByteBuff.readIndex(readIndex);
                discardReadBytes(mByteBuff);
                break;
            }

            // 解析出了数据，但 readIndex 没有变化，视为异常情况
            CHECK(mByteBuff.readIndex() != readIndex, "no bytes consumed but has data !")

            for (auto &item: mOutList) {
                ctx.fireChannelRead(std::move(item));
            }
            mOutList.clear();

            if (ctx.isRemoved()) {
                break;
            }
        }
    }

    void handlerRemoved(ChannelHandlerContext &ctx) noexcept override
    {
        // 把剩下的未解析的数据发出去
        if (ctx.pipeline().isActive() && mByteBuff.readableBytes() > 0) {
            auto msg = makeAny<ByteBuf>();
            mByteBuff.swap(*msg->as<ByteBuf>());
            ctx.fireChannelRead(std::move(msg));
        }
    }

public:
    explicit ByteToMessageDecoder() noexcept = default;
    NO_COPY(ByteToMessageDecoder)
};

template <typename State>
class ReplayingDecoder: public ByteToMessageDecoder {
    State mState;
    int mCheckpoint = -1;
    ByteBuf *mUsingByteBuf = nullptr;
protected:
    State state() const noexcept { return mState; }

    void state(State state) noexcept { mState = std::move(state); }

    void checkpoint(State state) noexcept {
        assert(mUsingByteBuf != nullptr);
        mCheckpoint = mUsingByteBuf->readIndex();
        mState = state;
    }

    void callDecode(ChannelHandlerContext &ctx, ByteBuf &in, std::vector<AnyPtr> &out) noexcept override {
        assert(mUsingByteBuf == nullptr);
        mUsingByteBuf = &in;

        if (mCheckpoint >= 0) {
            in.readIndex(mCheckpoint);
        }

        ByteToMessageDecoder::callDecode(ctx, in, out);

        assert(mUsingByteBuf == &in);
        mUsingByteBuf = nullptr;
    }

    void discardReadBytes(hysburg::ByteBuf &in) noexcept override {
        auto readIndex = in.readIndex();
        ByteToMessageDecoder::discardReadBytes(in);
        if (mCheckpoint >= 0) {
            mCheckpoint -= readIndex;
            assert(mCheckpoint >= 0);
        }
    }

public:
    explicit ReplayingDecoder() noexcept = default;

    explicit ReplayingDecoder(State state) noexcept: mState(state) {
    }
    NO_COPY(ReplayingDecoder)
};


template<typename MsgType>
class MessageToByteEncoder: public ChannelOutboundHandler
{
    template<typename T>
    void callEncode(ChannelHandlerContext &ctx, Any &msg, ByteBuf &out) noexcept {
        encode(ctx, *msg.as<T>(), out);
    }

    template<>
    void callEncode<Any>(ChannelHandlerContext &ctx, Any &msg, ByteBuf &out) noexcept {
        encode(ctx, msg, out);
    }

protected:
    virtual bool acceptOutboundMessage(Any &msg) noexcept {
        return msg.is<MsgType>();
    }

    virtual void encode(ChannelHandlerContext &ctx, MsgType &msg, ByteBuf &out) noexcept = 0;

    void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) noexcept override {
        if (!acceptOutboundMessage(*msg)) {
            ctx.write(std::move(msg), std::move(promise));
            return;
        }
        auto byteBuf = makeAny<ByteBuf>();
        callEncode<MsgType>(ctx, *msg, *byteBuf->as<ByteBuf>());
        ctx.write(std::move(byteBuf), std::move(promise));
    }
public:
    explicit MessageToByteEncoder() noexcept = default;
    NO_COPY(MessageToByteEncoder)
};


class MessageToMessageCodec: public ChannelDuplexHandler
{
protected:
    using MessageList = std::vector<AnyPtr>;
    virtual void decode(ChannelHandlerContext &ctx, Any &msg, MessageList &out) = 0;
    virtual void encode(ChannelHandlerContext &ctx, Any &msg, MessageList &out) = 0;
    virtual bool acceptInboundMessage(Any &msg) const noexcept = 0;
    virtual bool acceptOutboundMessage(Any &msg) const noexcept = 0;

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override {
        if (!acceptInboundMessage(*msg)) {
            ctx.fireChannelRead(std::move(msg));
            return;
        }
        MessageList list;
        decode(ctx, *msg, list);
        for (auto &item: list) {
            ctx.fireChannelRead(std::move(item));
        }
    }

    void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) noexcept override
    {
        if (!acceptOutboundMessage(*msg)) {
            ctx.write(std::move(msg), std::move(promise));
            return;
        }
        MessageList list;
        encode(ctx, *msg, list);
        for (auto &item: list) {
            ctx.write(std::move(item), std::move(promise));
        }
    }
public:
    explicit MessageToMessageCodec() noexcept = default;
    NO_COPY(MessageToMessageCodec)
};

class CombinedChannelDuplexHandler: public ChannelDuplexHandler
{
    ChannelHandlerPtr mInboundHandler;
    ChannelHandlerPtr mOutboundHandler;

protected:
    void init(ChannelHandlerPtr in, ChannelHandlerPtr out) noexcept
    {
        CHECK(mInboundHandler == nullptr && mOutboundHandler == nullptr, "duplicated call")
        CHECK(in != nullptr && out != nullptr, "nullptr in='%p', out='%p'", in.get(), out.get())

        CHECK(in->isInbounds(), "'%p' is NOT inbounds handler", in.get())
        CHECK(out->isOutbounds(), "'%p' is NOT outbounds handler", out.get())

        mInboundHandler = std::move(in);
        mOutboundHandler = std::move(out);
    }

    void handlerAdded(ChannelHandlerContext &ctx) noexcept override
    {
        if (mInboundHandler == nullptr) {
            return;
        }
        mInboundHandler->handlerAdded(ctx);
    }

    void channelActive(ChannelHandlerContext &ctx) noexcept override
    {
        if (mInboundHandler == nullptr) {
            ctx.fireChannelActive();
            return;
        }
        mInboundHandler->channelActive(ctx);
    }

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override
    {
        if (mInboundHandler == nullptr) {
            ctx.fireChannelRead(std::move(msg));
            return;
        }
        mInboundHandler->channelRead(ctx, std::move(msg));
    }

    void userEventTriggered(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override
    {
        if (mInboundHandler == nullptr) {
            ctx.fireUserEvent(std::move(msg));
            return;
        }
        mInboundHandler->userEventTriggered(ctx, std::move(msg));
    }

    void channelInactive(ChannelHandlerContext &ctx) noexcept override
    {
        if (mInboundHandler == nullptr) {
            ctx.fireChannelInactive();
            return;
        }
        mInboundHandler->channelInactive(ctx);
    }

    void handlerRemoved(ChannelHandlerContext &ctx) noexcept override
    {
        if (mInboundHandler == nullptr) {
            return;
        }
        mInboundHandler->handlerRemoved(ctx);
    }

    void write(ChannelHandlerContext &ctx, AnyPtr msg, PromisePtr<void> promise) noexcept override
    {
        if (mOutboundHandler == nullptr) {
            ctx.write(std::move(msg), std::move(promise));
            return;
        }
        mOutboundHandler->write(ctx, std::move(msg), std::move(promise));
    }

    void close(ChannelHandlerContext &ctx) noexcept override
    {
        if (mOutboundHandler == nullptr) {
            ctx.close();
            return;
        }
        mOutboundHandler->close(ctx);
    }

public:
    explicit CombinedChannelDuplexHandler() noexcept = default;

    explicit CombinedChannelDuplexHandler(ChannelHandlerPtr inbound, ChannelHandlerPtr outbound) noexcept
    {
        init(std::move(inbound), std::move(outbound));
    }
    NO_COPY(CombinedChannelDuplexHandler)
};

template <typename MsgType>
class SimpleInboundChannelHandler: public ChannelInboundHandler
{
    template<typename T>
    bool isType(Any &msg) const noexcept { return msg.is<T>(); }

    template<>
    bool isType<Any>(Any &msg) const noexcept { return true; }

protected:
    virtual bool acceptInboundMessage(Any &msg) noexcept {
        return isType<MsgType>(msg);
    }

    virtual void channelRead0(ChannelHandlerContext &ctx, MsgType &msg) noexcept = 0;

    void channelRead(ChannelHandlerContext &ctx, AnyPtr msg) noexcept override
    {
        if (!acceptInboundMessage(*msg)) {
            ctx.fireChannelRead(std::move(msg));
            return;
        }
        channelRead0(ctx, *msg->as<MsgType>());
    }
public:
    explicit SimpleInboundChannelHandler() noexcept = default;
    NO_COPY(SimpleInboundChannelHandler)
};


}


#endif // HYSBURG_CHANNEL_HANDLER_HPP