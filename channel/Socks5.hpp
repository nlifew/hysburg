
#ifndef HYSBURG_SOCKS5_HPP
#define HYSBURG_SOCKS5_HPP

#include "ChannelHandler.hpp"

namespace hysburg
{

enum SocksVersion
{
    _5 = 5,
};

enum Socks5AuthMethod
{
    NO_AUTH = 0x00,
    GSSAPI = 0x01,
    USERNAME_PASSWORD = 0x02,
    IANA_ASSIGNED_BEGIN = 0x03,
    IANA_ASSIGNED_END = 0x7f,
    PRIVATE_METHOD_BEGIN = 0x80,
    PRIVATE_METHOD_END = 0xfe,
    NO_ACCEPTABLE = 0xff,
};

struct Socks5InitialRequest
{
    bool success = true;
    std::vector<Socks5AuthMethod> authMethods;
};

struct Socks5InitialResponse
{
    bool success = true;
    Socks5AuthMethod authMethod = NO_AUTH;
};

enum Socks5Command
{
    CONNECT = 0x01,
    BIND = 0x02,
    UDP = 0x03,
};

enum Socks5AddressType
{
    IPV4 = 0x01,
    DOMAIN_NAME = 0x03,
    IPV6 = 0x04,
};


struct Socks5CommandBase
{
    bool success = true;

    Socks5AddressType type = Socks5AddressType::IPV4;
    uint8_t ipv4[4] {};
    uint8_t ipv6[16] {};
    std::string domain;
    uint16_t port = 0;

    [[nodiscard]]
    std::string toString() const
    {
        std::string str = addrToString();
        char tmp[16] = { 0 };
        snprintf(tmp, sizeof(tmp), ":%d", port);
        str.append(tmp);
        return str;
    }

    [[nodiscard]]
    std::string addrToString() const
    {
        switch (type) {
            case Socks5AddressType::IPV4: {
                char tmp[64] = { 0 };
                inet_ntop(AF_INET, ipv4, tmp, sizeof(tmp));
                return tmp;
            }
            case Socks5AddressType::DOMAIN_NAME: {
                return domain;
            }
            case Socks5AddressType::IPV6: {
                char tmp[256] = { 0 };
                inet_net_ntop(AF_INET6, ipv6, sizeof(ipv6), tmp, sizeof(tmp));
                return tmp;
            }
            default: return "";
        }
    }
};

struct Socks5CommandRequest: Socks5CommandBase
{
    Socks5Command cmd = Socks5Command::CONNECT;
};


enum Socks5Reply
{
    SUCCESS = 0,
    GENERAL_SOCKS_SERVER_FAILURE = 1,
    CONNECTION_NOT_ALLOWED = 2,
    NETWORK_UNREACHABLE = 3,
    HOST_UNREACHABLE = 4,
    CONNECTION_REFUSED = 5,
    TTL_EXPIRED = 6,
    COMMAND_NOT_SUPPORTED = 7,
    ADDRESS_TYPE_NOT_SUPPORTED = 8,
};

struct Socks5CommandResponse: Socks5CommandBase
{
    Socks5Reply reply = Socks5Reply::SUCCESS;

    Socks5CommandResponse() = default;
    explicit Socks5CommandResponse(Socks5Reply reply)
        : reply(reply) {
    }
};

template<typename MsgTypeName>
class Socks5MsgDecoder: public ByteToMessageDecoder
{
     AnyPtr mSocks5Msg;
     int mErrno = ERRNO_CONTINUE;
protected:
    static constexpr int ERRNO_OK = 0;
    static constexpr int ERRNO_FAILURE = -1;
    static constexpr int ERRNO_CONTINUE = -2;

    virtual int decodeSocks5Msg(MsgTypeName &socks5Msg, ByteBuf &in) = 0;

    void decode(ChannelHandlerContext &, ByteBuf &in, std::vector<AnyPtr> &out) override
    {
        if (mErrno != ERRNO_CONTINUE) {
            AnyPtr any;
            auto byteBuf = makeAnyIn<ByteBuf>(any);
            byteBuf->swap(in);
            out.emplace_back(std::move(any));
            return;
        }

        if (mSocks5Msg == nullptr) {
            mSocks5Msg = makeAny<MsgTypeName>();
        }

        mErrno = decodeSocks5Msg(*mSocks5Msg->as<MsgTypeName>(), in);
        switch (mErrno) {
            case ERRNO_OK: {
                mSocks5Msg->as<MsgTypeName>()->success = true;
                out.emplace_back(std::move(mSocks5Msg));
                break;
            }
            case ERRNO_FAILURE: {
                mSocks5Msg->as<MsgTypeName>()->success = false;
                out.emplace_back(std::move(mSocks5Msg));
                break;
            }
            default: return;
        }
    }
};

class Socks5InitRequestDecoder: public Socks5MsgDecoder<Socks5InitialRequest>
{
    int decodeSocks5Msg(Socks5InitialRequest &socks5Msg, ByteBuf &in) override
    {
        // ver
        if (auto version = in.readByte(); version != SocksVersion::_5) {
            LOGE("invalid socks version: '%d', expected: '%d'", version, SocksVersion::_5);
            return ERRNO_FAILURE;
        }
        // auth methods num
        if (in.readableBytes() < 1) {
            return ERRNO_CONTINUE;
        }
        auto n = in.readByte();
        // auth methods
        if (in.readableBytes() < n) {
            return ERRNO_CONTINUE;
        }
        socks5Msg.authMethods.resize(n);
        in.readBytes(socks5Msg.authMethods.data(), n);
        return ERRNO_OK;
    }

public:
    explicit Socks5InitRequestDecoder() = default;
    NO_COPY(Socks5InitRequestDecoder)
};

class Socks5InitResponseDecoder: public Socks5MsgDecoder<Socks5InitialResponse>
{
    int decodeSocks5Msg(Socks5InitialResponse &socks5Msg, ByteBuf &in) override
    {
        // ver
        if (auto version = in.readByte(); version != SocksVersion::_5) {
            LOGE("invalid socks version: '%d', expected: '%d'", version, SocksVersion::_5);
            return ERRNO_FAILURE;
        }
        // auth method
        if (in.readableBytes() < 1) {
            return ERRNO_CONTINUE;
        }
        socks5Msg.authMethod = static_cast<Socks5AuthMethod>(in.readByte());
        return ERRNO_OK;
    }
public:
    explicit Socks5InitResponseDecoder() = default;
    NO_COPY(Socks5InitResponseDecoder)
};

template<typename MsgTypeName>
class Socks5CommandDecoder: public Socks5MsgDecoder<MsgTypeName>
{
    void decodeCmdOrReply(Socks5CommandRequest &request, ByteBuf &in)
    {
        request.cmd = static_cast<Socks5Command>(in.readByte());
    }

    void decodeCmdOrReply(Socks5CommandResponse &response, ByteBuf &in)
    {
        response.reply = static_cast<Socks5Reply>(in.readByte());
    }

    using Socks5MsgDecoder<MsgTypeName>::ERRNO_FAILURE;
    using Socks5MsgDecoder<MsgTypeName>::ERRNO_OK;
    using Socks5MsgDecoder<MsgTypeName>::ERRNO_CONTINUE;

    int decodeSocks5Msg(MsgTypeName &socks5Msg, ByteBuf &in) override
    {
        // ver
        if (auto ver = in.readByte(); ver != SocksVersion::_5) {
            LOGE("invalid socks version: '%d', expected '%d'", ver, SocksVersion::_5);
            return ERRNO_FAILURE;
        }
        // cmd
        if (in.readableBytes() < 1) {
            return ERRNO_CONTINUE;
        }

        // cmd or reply
        decodeCmdOrReply(socks5Msg, in);

        // rsv
        if (in.readableBytes() < 1) {
            return ERRNO_CONTINUE;
        }
        in.readByte();
        // atyp
        if (in.readableBytes() < 1) {
            return ERRNO_CONTINUE;
        }
        socks5Msg.type = static_cast<Socks5AddressType>(in.readByte());
        // dst.addr
        switch (socks5Msg.type) {
            case Socks5AddressType::IPV4: {
                if (in.readableBytes() < sizeof(socks5Msg.ipv4)) {
                    return ERRNO_CONTINUE;
                }
                in.readBytes(socks5Msg.ipv4, sizeof(socks5Msg.ipv4));
                break;
            }
            case Socks5AddressType::DOMAIN_NAME: {
                if (in.readableBytes() < 1) {
                    return ERRNO_CONTINUE;
                }
                auto len = in.readByte();
                if (in.readableBytes() < len) {
                    return ERRNO_CONTINUE;
                }
                socks5Msg.domain.resize(len);
                in.readBytes(socks5Msg.domain.data(), len);
                break;
            }
            case Socks5AddressType::IPV6: {
                if (in.readableBytes() < sizeof(socks5Msg.ipv6)) {
                    return ERRNO_CONTINUE;
                }
                in.readBytes(socks5Msg.ipv6, sizeof(socks5Msg.ipv6));
                break;
            }
            default: {
                LOGE("unknown atyp: '%d'", socks5Msg.type);
                return ERRNO_FAILURE;
            }
        }
        // dst.port
        if (in.readableBytes() < 2) {
            return ERRNO_CONTINUE;
        }
        socks5Msg.port = in.readShort();
        return ERRNO_OK;
    }
};

using Socks5CommandRequestDecoder = Socks5CommandDecoder<Socks5CommandRequest>;
using Socks5CommandResponseDecoder = Socks5CommandDecoder<Socks5CommandResponse>;


class Socks5MsgEncoder: public MessageToByteEncoder<Any>
{
    enum SupportedType
    {
        Type_Unsupported = -1,
        Type_Socks5InitialRequest,
        Type_Socks5InitialResponse,
        Type_Socks5CommandRequest,
        Type_Socks5CommandResponse,
    };

    static SupportedType checkType(Any &msg)
    {
        if (msg.type == typeid(Socks5InitialRequest)) {
            return Type_Socks5InitialRequest;
        }
        if (msg.type == typeid(Socks5InitialResponse)) {
            return Type_Socks5InitialResponse;
        }
        if (msg.type == typeid(Socks5CommandRequest)) {
            return Type_Socks5CommandRequest;
        }
        if (msg.type == typeid(Socks5CommandResponse)) {
            return Type_Socks5CommandResponse;
        }
        return Type_Unsupported;
    }

    SupportedType mMsgType = Type_Unsupported;

    bool acceptOutboundMessage(Any &msg) override
    {
        return (mMsgType = checkType(msg)) != Type_Unsupported;
    }

    void encode(ChannelHandlerContext &, Any &msg, ByteBuf &out) override
    {
        out.writeByte(SocksVersion::_5);

        switch (mMsgType) {
            case Type_Socks5InitialRequest: {
                auto *request = msg.as<Socks5InitialRequest>();
                out.writeByte(static_cast<int8_t>(request->authMethods.size()));
                out.writeBytes(request->authMethods.data(), request->authMethods.size());
                break;
            }
            case Type_Socks5InitialResponse: {
                auto *response = msg.as<Socks5InitialResponse>();
                out.writeByte(response->authMethod);
                break;
            }
            case Type_Socks5CommandRequest:
            case Type_Socks5CommandResponse: {
                auto *request = msg.as<Socks5CommandRequest>();
                auto *response = msg.as<Socks5CommandResponse>();
                out.writeByte(
                    mMsgType == Type_Socks5CommandRequest ?
                    static_cast<int8_t>(request->cmd) :
                    static_cast<int8_t>(response->reply)
                );
                out.writeByte(0x00);
                out.writeByte(request->type);
                switch (request->type) {
                    case Socks5AddressType::IPV4: {
                        out.writeBytes(request->ipv4, sizeof(request->ipv4));
                        break;
                    }
                    case Socks5AddressType::DOMAIN_NAME: {
                        out.writeByte( static_cast<int8_t>(request->domain.size()));
                        out.writeBytes(request->domain.data(), request->domain.size());
                        break;
                    }
                    case Socks5AddressType::IPV6: {
                        out.writeBytes(request->ipv6, sizeof(request->ipv6));
                        break;
                    }
                }
                out.writeShort(static_cast<int16_t>(request->port));
                break;
            }
            default: break;
        }
    }
public:
    explicit Socks5MsgEncoder() = default;
    NO_COPY(Socks5MsgEncoder)
};

}

#endif // HYSBURG_SOCKS5_HPP
