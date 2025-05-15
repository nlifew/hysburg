#ifndef HYSBURG_CHANNEL_HTTP_OBJECT
#define HYSBURG_CHANNEL_HTTP_OBJECT

#include <string>
#include <map>

#include "ChannelHandler.hpp"
#include "third_party/picohttpparser/picohttpparser.h"

namespace hysburg
{

struct HttpObject
{
    bool isSuccess = true;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct HttpRequest: public HttpObject
{
    std::string path = "/";
    std::string method = "GET";
};

struct HttpResponse: public HttpObject
{
// 定义宏，用于生成枚举项和消息映射
#define HTTP_STATUS_CODES(XX) \
    XX(200, OK, "OK") \
    XX(400, BAD_REQUEST, "Bad Request") \
    XX(403, FORBIDDEN, "Forbidden") \
    XX(404, NOT_FOUND, "Not Found") \
    XX(405, METHOD_NOT_ALLOWED, "Method Not Allowed")

    // 状态码定义
    using HttpCode = uint32_t;

#define XX(num, name, string) static constexpr HttpCode CODE_##name = num;
    HTTP_STATUS_CODES(XX)
#undef XX

    uint32_t code = CODE_OK;

    [[nodiscard]]
    const char *message() const noexcept { return getMessageByCode(code); }

    static const char *getMessageByCode(HttpCode code)
    {
        switch (code) {
#define XX(num, name, string) case num: return string;
            HTTP_STATUS_CODES(XX)
#undef XX
            default:
                LOGI("unknown response code: %d", code);
        }
        return "";
    }
};

/**
 * [HttpObject] 解析器，会向下游抛出 [HttpObjectType] 类型
 */
template <typename HttpObjectType>
class HttpObjectDecoder: public ReplayingDecoder<int>
{
    using Super = ReplayingDecoder<int>;
    AnyPtr mHttpObject;

protected:
    enum State
    {
        DECODE_HEADER = 1,
        DECODE_BODY = 2,
        DECODE_DONE = 3,
        DECODE_ERROR = -1,
    };
    enum Errno
    {
        FAILURE = -1,
        CONTINUE = -2,
        TOO_LARGE_HEADER = -3,
        TOO_LARGE_BODY = -4,
        INVALID_VERSION = -5,
    };

    size_t mLastBuffLen = 0;

    static std::string &trimKey(std::string &key)
    {
        for (auto &c : key) {
            c = (char) std::tolower(c);
        }
        return key;
    }

    static void setHeaders(HttpObject &out, const phr_header *headerArray, size_t headerArrayLen)
    {
        out.headers.clear();
        for (size_t i = 0; i < headerArrayLen; ++i) {
            std::string key(headerArray[i].name, headerArray[i].name_len);
            trimKey(key);
            out.headers.emplace(std::move(key), std::string(headerArray[i].value, headerArray[i].value_len));
        }
    }

    virtual ssize_t decodeHeader(ChannelHandlerContext &ctx, ByteBuf &in, HttpObjectType &out) noexcept = 0;

    virtual ssize_t decodeBody(ChannelHandlerContext &, ByteBuf &in, HttpObjectType &out) noexcept
    {
        // 只支持 Content-Length，不支持 chunk 编码
        // 使用 std::map.find() 不污染原始请求头
        size_t contentLength = 0;
        {
            const auto it = out.headers.find("content-length");
            if (it != out.headers.end()) {
                contentLength = (size_t) Strings::toInt(it->second);
            }
        }
        if (contentLength > maxBodySize) {
            return TOO_LARGE_BODY;
        }
        if (in.readableBytes() < contentLength) {
            return CONTINUE;
        }
        out.body.resize(contentLength);
        in.readBytes(out.body.data(), contentLength);
        return (ssize_t) contentLength;
    }

    void decode(ChannelHandlerContext &ctx, ByteBuf &in, std::vector<AnyPtr> &out) noexcept override {
        switch ((State) state()) {
            case DECODE_HEADER: {
                if (mHttpObject == nullptr) {
                    mHttpObject = makeAny<HttpObjectType>();
                }
                ssize_t ret = decodeHeader(ctx, in, *mHttpObject->as<HttpObjectType>());
                if (ret == CONTINUE) {
                    break;
                }
                if (ret < 0) {
                    state(State::DECODE_ERROR);
                    break;
                }
                in.readIndex(in.readIndex() + ret);
                checkpoint(State::DECODE_BODY);
                [[fallthrough]];
            }
            case DECODE_BODY: {
                ssize_t ret = decodeBody(ctx, in, *mHttpObject->as<HttpObjectType>());
                if (ret == CONTINUE) {
                    break;
                }
                if (ret < 0) {
                    state(State::DECODE_ERROR);
                    break;
                }
                checkpoint(State::DECODE_DONE);
                [[fallthrough]];
            }
            case DECODE_DONE: {
                mLastBuffLen = 0;
                out.emplace_back(std::move(mHttpObject));
                checkpoint(State::DECODE_HEADER);
                break;
            }
            default: break;
        }
        if (state() == State::DECODE_ERROR) {
            // 失败，消费掉所有的内容，防止死循环和 assert 异常
            mHttpObject->as<HttpObjectType>()->isSuccess = false;
            in.readIndex(in.writeIndex());
            out.emplace_back(std::move(mHttpObject));
        }
    }

public:
    static constexpr size_t DEFAULT_MAX_HEADER_NUM = 32;
    static constexpr size_t DEFAULT_MAX_HEADER_SIZE = 64 * 1024;
    static constexpr size_t DEFAULT_MAX_BODY_SIZE = 1 * 1024 * 1024;

    size_t maxHeaderSize = DEFAULT_MAX_HEADER_SIZE;
    size_t maxHeaderNum = DEFAULT_MAX_HEADER_NUM;
    size_t maxBodySize = DEFAULT_MAX_BODY_SIZE;

    explicit HttpObjectDecoder() noexcept: Super(State::DECODE_HEADER) {
    }
    NO_COPY(HttpObjectDecoder)
};


class HttpRequestDecoder: public HttpObjectDecoder<HttpRequest>
{
protected:
    ssize_t decodeHeader(ChannelHandlerContext &, ByteBuf &in, HttpRequest &out) noexcept override
    {
        const char *methodString = ""; size_t methodStringLen = 0;
        const char *pathString = ""; size_t pathStringLen = 0;
        int minorVersion = 0;

        std::vector<phr_header> headerArray(maxHeaderNum);
        size_t headerArrayLen = maxHeaderNum;

        size_t readIndex = in.readIndex();
        size_t availableBytes = std::min(in.readableBytes(), maxHeaderSize);

        int ret = phr_parse_request(
                (char *) in.data() + in.readIndex(),
                availableBytes,
                &methodString, &methodStringLen,
                &pathString, &pathStringLen,
                &minorVersion,
                headerArray.data(), &headerArrayLen,
                mLastBuffLen);
        mLastBuffLen = availableBytes;

        if (ret == -1) {
            // 有错误直接返回
            return FAILURE;
        }
        if (ret == -2) {
            // 需要更多数据
            if (in.readIndex() - readIndex >= maxHeaderSize) {
                // 超出了最大请求头长度，直接返回
                return TOO_LARGE_HEADER;
            }
            return CONTINUE;
        }
        // 检查支持的版本
        if (minorVersion != 1) {
            return INVALID_VERSION;
        }
        // 规范化字段
        out.method.assign(methodString, methodStringLen);
        Strings::unsafeToUpper(out.method.data(), out.method.size());

        out.path.assign(pathString, pathStringLen);
        setHeaders(out, headerArray.data(), headerArrayLen);
        return ret;
    }
};

class HttpResponseDecoder: public HttpObjectDecoder<HttpResponse>
{
protected:
    ssize_t decodeHeader(ChannelHandlerContext &, ByteBuf &in, HttpResponse &out) noexcept override
    {
        const char *msgString = "";
        size_t msgStringLen = 0;
        int minorVersion = 0;

        std::vector<phr_header> headerArray(maxHeaderNum);
        size_t headerArrayLen = maxHeaderNum;

        size_t readIndex = in.readIndex();
        size_t availableBytes = std::min(in.readableBytes(), maxHeaderSize);

        int ret = phr_parse_response(
                (char *) in.data() + in.readIndex(),
                availableBytes, &minorVersion,
                (int *) &out.code, &msgString, &msgStringLen,
                headerArray.data(), &headerArrayLen, mLastBuffLen);
        mLastBuffLen = availableBytes;

        if (ret == -1) {
            return FAILURE;
        }
        if (ret == -2) {
            // 需要更多数据
            if (in.readIndex() - readIndex >= maxHeaderSize) {
                // 超出了最大请求头长度，直接返回
                return TOO_LARGE_HEADER;
            }
            return CONTINUE;
        }

        // 检查支持的版本
        if (minorVersion != 1) {
            return INVALID_VERSION;
        }
        // 检查 msg 是否符合
//        std::string msg(msgString, msgStringLen);
//        if (strcasecmp(msg.data(), HttpResponse::getMessageByCode(out.code)) != 0) {
//            return FAILURE;
//        }
        // 请求头
        setHeaders(out, headerArray.data(), headerArrayLen);
        return ret;
    }
};

template <typename HttpObjectType>
class HttpObjectEncoder: public MessageToByteEncoder<HttpObjectType>
{
protected:
    virtual void writeStatusLine(ChannelHandlerContext &, HttpObjectType &msg, ByteBuf &out) noexcept = 0;

    void encode(ChannelHandlerContext &ctx, HttpObjectType &msg, ByteBuf &out) noexcept override
    {
        writeStatusLine(ctx, msg, out);
        msg.headers["content-length"] = std::to_string(msg.body.size());
        for (const auto &it : msg.headers) {
            out.writeBytes(it.first);
            out.writeBytes(": ");
            out.writeBytes(it.second);
            out.writeBytes("\r\n");
        }
        out.writeBytes("\r\n");
        out.writeBytes(msg.body.data(), msg.body.size());
    }
};


class HttpRequestEncoder: public HttpObjectEncoder<HttpRequest>
{
protected:
    void writeStatusLine(ChannelHandlerContext &, HttpRequest &msg, ByteBuf &out) noexcept override
    {
        out.writeBytes(msg.method);
        out.writeBytes(" ");
        out.writeBytes(msg.path);
        out.writeBytes(" HTTP/1.1\r\n");
    }
};

class HttpResponseEncoder: public HttpObjectEncoder<HttpResponse>
{
protected:
    void writeStatusLine(ChannelHandlerContext &, HttpResponse &msg, ByteBuf &out) noexcept override
    {
        out.writeBytes("HTTP/1.1 ");
        out.writeBytes(std::to_string(msg.code));
        out.writeBytes(" ");
        out.writeBytes(HttpResponse::getMessageByCode(msg.code));
        out.writeBytes("\r\n");
    }
};

class HttpClientCodec: public CombinedChannelDuplexHandler
{
public:
    explicit HttpClientCodec() noexcept {
        init(std::make_shared<HttpResponseDecoder>(), std::make_shared<HttpRequestEncoder>());
    }
    NO_COPY(HttpClientCodec)
};

class HttpServerCodec: public CombinedChannelDuplexHandler
{
public:
    explicit HttpServerCodec() noexcept {
        init(std::make_shared<HttpRequestDecoder>(), std::make_shared<HttpResponseEncoder>());
    }
    NO_COPY(HttpServerCodec)
};

}


#endif // HYSBURG_CHANNEL_HTTP_OBJECT