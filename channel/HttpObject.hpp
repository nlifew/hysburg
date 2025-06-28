#ifndef HYSBURG_CHANNEL_HTTP_OBJECT
#define HYSBURG_CHANNEL_HTTP_OBJECT

#include <string>
#include <vector>
#include <llhttp.h>

#include "ChannelHandler.hpp"

namespace hysburg
{

class HttpObject
{
    template<typename, llhttp_type_t>
    friend class HttpObjectDecoder;

protected:
    static constexpr size_t INVALID_OFFSET = (size_t) -1;

    struct StringRef {
        size_t off = INVALID_OFFSET;
        size_t len = 0;

        [[nodiscard]]
        std::string_view get(const ByteBuf &buf) const noexcept {
            return off == INVALID_OFFSET ?
                std::string_view {  } :
                std::string_view { (const char*) buf.data() + off, len };
        }
    };

    static void trimKey(const StringRef &str, ByteBuf &buf) noexcept {
        trimKey(str, (char*) buf.data());
    }
    static void trimKey(const StringRef &str, char *buf) noexcept {
        auto data = buf + str.off;
        for (size_t i = 0; i < str.len; i ++) {
            data[i] = (char) std::tolower(data[i]);
        }
    }

    using Header = std::pair<StringRef, StringRef>;

    ByteBuf mRaw;
    bool mSuccess = true;
    std::vector<Header> mHeaders;
    StringRef mBody;

    [[nodiscard]]
    bool ownThisString(const std::string_view &str) const noexcept {
        auto from = (char *) mRaw.data();
        auto to = (char *) mRaw.data() + mRaw.writeIndex();
        return from <= str.data() && str.data() <= to;
    }

    [[nodiscard]]
    StringRef update(const StringRef &oldValue, const std::string_view &newValue) noexcept {
        // FIXME 优化
//        if (ownThisString(oldValue) && oldValue.size() >= newValue.size()) {
//            // 备份当前 wIndex
//            auto wIndex = mRaw.writeIndex();
//            // 移动指针，跳转到 oldValue 的位置
//            mRaw.writeIndex(oldValue.data() - (char *) mRaw.data());
//            // 写入二进制数据
//            mRaw.writeBytes(newValue);
//            // 还原 wIndex
//            mRaw.writeIndex(wIndex);
//            // 可以返回了
//            return { oldValue.data(), newValue.size() };
//        }
//
        // 直接在后面插入
        auto off = mRaw.writeIndex();
        mRaw.writeBytes(newValue);
        return { off, newValue.size() };
    }
public:
    virtual ~HttpObject() noexcept = default;

    std::string_view header(const std::string_view &name) noexcept {
        auto it = std::find_if(mHeaders.begin(), mHeaders.end(), [&name, this](Header &it) -> bool {
            return name == it.first.get(mRaw);
        });
        if (it == mHeaders.end()) {
            return "";
        }
        return it->second.get(mRaw);
    }

    std::vector<std::pair<std::string_view, std::string_view>> headers() noexcept {
        std::vector<std::pair<std::string_view, std::string_view>> vec(mHeaders.size());
        for (size_t i = 0; i < mHeaders.size(); i ++) {
            auto &header = mHeaders[i];
            vec[i] = std::make_pair(header.first.get(mRaw), header.second.get(mRaw));
        }
        return vec;
    }

    void header(const std::string_view &name, const std::string_view &value) noexcept {
        auto it = std::find_if(mHeaders.begin(), mHeaders.end(), [&name, this](Header &it) -> bool {
            return name == it.first.get(mRaw);
        });
        if (it != mHeaders.end()) {
            it->second = update(it->second, value);
            return;
        }
        auto newName = update(StringRef(), name);
        trimKey(newName, mRaw);

        mHeaders.emplace_back(newName, update(StringRef(), value));
    }

    [[nodiscard]]
    bool isSuccess() const noexcept { return mSuccess; }

    std::string_view body() noexcept { return mBody.get(mRaw); }

    void body(const std::string_view &newBody) noexcept {
        mBody = update(mBody, newBody);
    }
};

class HttpRequest: public HttpObject
{
private:
    friend class HttpRequestDecoder;
    StringRef mPath;
    StringRef mMethod;
public:
    void path(const std::string_view &newPath) noexcept {
        mPath = update(mPath, newPath);
    }

    void method(const std::string_view &newMethod) noexcept {
        mMethod = update(mMethod, newMethod);
    }

    std::string_view path() noexcept { return mPath.get(mRaw); }
    std::string_view method() noexcept { return mMethod.get(mRaw); }

    explicit HttpRequest() noexcept {
        path("/");
        method("GET");
    }
};

class HttpResponse: public HttpObject
{
    friend class HttpResponseDecoder;
public:
    // 状态码定义
    using HttpCode = llhttp_status_t;

private:
    HttpCode mCode = HttpCode::HTTP_STATUS_OK;
    StringRef mMessage;

public:
    explicit HttpResponse() noexcept {
        message("OK");
    }

    [[nodiscard]]
    std::string_view message() const noexcept { return getMessageByCode(mCode); }

    static std::string_view getMessageByCode(HttpCode code) {
        return llhttp_status_name(code);
    }

    [[nodiscard]]
    HttpCode code() const noexcept { return mCode; }

    void code(HttpCode newCode) noexcept { mCode = newCode; }

    [[nodiscard]]
    std::string_view message() noexcept { return mMessage.get(mRaw); }

    void message(const std::string_view &newMessage) noexcept {
        mMessage = update(mMessage, newMessage);
    }
};


/**
 * [HttpObject] 解析器，会向下游抛出 [HttpObjectType] 类型
 */
template <typename HttpObjectType, llhttp_type_t HttpParserType>
class HttpObjectDecoder: public ByteToMessageDecoder
{
protected:
    using StringRef = HttpObject::StringRef;
    static constexpr size_t INVALID_OFFSET = HttpObject::INVALID_OFFSET;

    size_t offsetOfData(const char *at) const noexcept {
        assert(mData != nullptr);
        return at - mData;
    }

    void updateString(StringRef &out, const char *at, size_t length) const noexcept {
        auto offset = offsetOfData(at);
        // 可能读到不完整的片段
        if (out.off == INVALID_OFFSET) {
            out.off = offset;
            out.len = length;
            return;
        }
        assert(out.off + out.len == offset);
        out.len += length;
    }

private:
    /**
     * headers、body 等都用偏移量记录。因为 ByteBuf 扩容过程中可能
     * 会改变 data 指针，这会导致指针悬垂，成为隐患
     */
    std::vector<std::pair<StringRef, StringRef>> mHeaders;
    StringRef mBody;
    StringRef mCurHeaderName;
    StringRef mCurHeaderValue;
    size_t mLastDecodedBytes = 0;
    char *mData = nullptr;
    bool mFirstUpgrade = true;

private:
    int on_message_begin() noexcept {
        mCurHeaderName = {};
        mCurHeaderValue = {};
        mBody = {};
        mHeaders.clear();
        assert(mData != nullptr);
        return 0;
    }

    int on_header_field(const char *at, size_t length) noexcept {
        if (mHeaders.size() > maxHeaderNum) {
            llhttp_set_error_reason(&mHttpParser, "access max header num");
            return -1;
        }
        if (!mHeaders.empty()) {
            size_t offset = offsetOfData(at);
            auto firstOffset = mHeaders[0].first.off;
            if (offset - firstOffset + length > maxHeaderSize) {
                llhttp_set_error_reason(&mHttpParser, "access max header size");
                return -1;
            }
        }
        // 可能读到不完整的片段
        updateString(mCurHeaderName, at, length);
        return 0;
    }

    int on_header_value(const char *at, size_t length) noexcept {
        if (!mHeaders.empty()) {
            size_t offset = offsetOfData(at);
            auto firstOffset = mHeaders[0].first.off;
            if (offset - firstOffset + length > maxHeaderSize) {
                llhttp_set_error_reason(&mHttpParser, "access max header size");
                return -1;
            }
        }
        updateString(mCurHeaderValue, at, length);
        return 0;
    }

    /**
     * 把当前 header 提交到 vector
     */
    int on_header_value_complete() noexcept {
        mHeaders.emplace_back(mCurHeaderName, mCurHeaderValue);
        mCurHeaderName = {};
        mCurHeaderValue = {};
        return 0;
    }

    int on_headers_complete() noexcept {
        if (mHttpParser.content_length > maxBodySize) {
            llhttp_set_error_reason(&mHttpParser, "access max body size");
            return -1;
        }
        for (auto &it : mHeaders) {
            HttpObject::trimKey(it.first, mData);
        }
        if (llhttp_get_upgrade(&mHttpParser)) {
            return 2;
        }
        return 0;
    }

    int on_body(const char *at, size_t length) noexcept {
        updateString(mBody, at, length);
        return 0;
    }

    /**
     * 当 http 消息解析完成的时候立即暂停 [HPE_PAUSED]，用来在 [llhttp_execute] 中快速返回。
     * 返回 HPE_PAUSED 的原因有以下几点：
     * 1. 消息可能有粘连，即一个 ByteBuf 中含有多个 http 请求。我们需要在解析完一个的时候及时暂停
     * 2. 得知当前解析器的 cursor 在哪 [llhttp_get_error_pos]，用来调整 ByteBuf 的指针
     */
    int on_message_complete() noexcept {
        if (llhttp_get_upgrade(&mHttpParser)) {
            return HPE_OK;
        }
        return HPE_PAUSED;
    }

#define LLHTTP_METHOD_BRIDGE(XX) \
    XX(on_message_begin)  \
    XX(on_message_complete) \
    XX(on_header_value_complete) \
    XX(on_headers_complete)

#define LLHTTP_DATA_METHOD_BRIDGE(XX) \
    XX(on_header_field) \
    XX(on_header_value) \
    XX(on_body)

    void initSettings() noexcept {
        llhttp_settings_init(&mSettings);
#define XX(NAME) \
        mSettings.NAME = [](llhttp_t *parser) -> int { \
            auto self = static_cast<HttpObjectDecoder*>(parser->data); \
            return self->NAME(); \
        };
            LLHTTP_METHOD_BRIDGE(XX)
#undef XX
#define XX(NAME) \
        mSettings.NAME = [](llhttp_t *parser, const char *at, size_t length) -> int { \
            auto self = static_cast<HttpObjectDecoder*>(parser->data); \
            return self->NAME(at, length); \
        };
            LLHTTP_DATA_METHOD_BRIDGE(XX)
#undef XX
        }

#undef LLHTTP_METHOD_BRIDGE
#undef LLHTTP_DATA_METHOD_BRIDGE

    llhttp_errno_t decode0(ChannelHandlerContext &ctx, ByteBuf &in) noexcept {
        // mData 指向数据开始的指针
        mData = (char *) in.readData();
        auto err = llhttp_execute(
                &mHttpParser,
                (char *) in.readData() + mLastDecodedBytes, // [1]
                in.readableBytes() - mLastDecodedBytes // [1]
        );
        mData = nullptr;
        // [1]. 如果 llhttp 上次解析到一半缓冲区就耗尽了，下次应该从结束的地方开始而不是从头开始

        auto errMsg = llhttp_get_error_reason(&mHttpParser);
        LOGE("decode result '%d(%s)' from '%s'",
             err, errMsg,ctx.channel().remoteAddrString().c_str()
        );
        return err;
    }

    void complete0(ByteBuf &byteBuf, std::vector<AnyPtr> &out) noexcept {
        // 现在指针的位置
        auto pos = llhttp_get_error_pos(&mHttpParser);
        // 整个对象的大小
        size_t httpObjectSize = pos - (char *) byteBuf.readData();

        // 把当前 byteBuf 拆分：pos 及之前的内容给 httpObject，之后的部分继续保留
        auto httpObjectMsg = makeAny<HttpObjectType>();
        auto httpObject = httpObjectMsg->template as<HttpObjectType>();
        if (byteBuf.readableBytes() == httpObjectSize) {
            httpObject->mRaw.swap(byteBuf);
        } else {
            httpObject->mRaw.writeBytes(byteBuf.readData(), httpObjectSize);
            byteBuf.readIndex(byteBuf.readIndex() + httpObjectSize);
            byteBuf.discardReadBytes();
        }

        // 把临时对象都塞进 http 对象里
        updateHttpObject(*httpObject);

        // 解析完成
        out.emplace_back(std::move(httpObjectMsg));

        // 还原状态，准备进行下一轮解析
        llhttp_resume(&mHttpParser);
        llhttp_set_error_reason(&mHttpParser, "");
        mLastDecodedBytes = 0;
    }

    void upgrade0(ByteBuf &byteBuf, std::vector<AnyPtr> &out) {
        // 消费掉 http 请求头部分
        if (mFirstUpgrade) {
            mFirstUpgrade = false;
            complete0(byteBuf, out);
            return;
        }
        // 直接抛出所有的字节
        auto tmp = makeAny<ByteBuf>();
        tmp->as<ByteBuf>()->swap(byteBuf);
        out.emplace_back(std::move(tmp));
    }

    void error0(ByteBuf &byteBuf, std::vector<AnyPtr> &out) {
        // 消费掉所有的内容，失败
        byteBuf.readIndex(byteBuf.writeIndex());
        auto tmp = makeAny<HttpObjectType>();
        tmp->template as<HttpObjectType>()->mSuccess = false;
        out.emplace_back(std::move(tmp));
    }

protected:
    llhttp_t mHttpParser {};
    llhttp_settings_t mSettings {};

    virtual void initParser() noexcept {
        initSettings();
        llhttp_init(&mHttpParser, HttpParserType, &mSettings);
        llhttp_set_lenient_optional_cr_before_lf(&mHttpParser, 1);
        mHttpParser.data = this;
    }

    virtual void updateHttpObject(HttpObjectType &httpObject) noexcept {
        std::swap(httpObject.mHeaders, mHeaders);
        std::swap(httpObject.mBody, mBody);
    }
public: // visible for test

    void decode(ChannelHandlerContext &ctx, ByteBuf &in, std::vector<AnyPtr> &out) noexcept override {
        if (mHttpParser.settings == nullptr) {
            initParser();
        }
        auto err = decode0(ctx, in);
        switch (err) {
            // 如果消息还不完整，等待下一条消息到来
            case HPE_OK:
                mLastDecodedBytes = in.readableBytes();
                break;
            // 如果成功读完了一条消息，解析这条消息
            case HPE_PAUSED:
                complete0(in, out);
                break;
            // 协议升级
            case HPE_PAUSED_UPGRADE:
                upgrade0(in, out);
                break;
            // 其余认为是失败
            default:
                error0(in, out);
                break;
        }
    }

public:
    static constexpr size_t DEFAULT_MAX_HEADER_NUM = 32;
    static constexpr size_t DEFAULT_MAX_HEADER_SIZE = 64 * 1024;
    static constexpr size_t DEFAULT_MAX_BODY_SIZE = 1 * 1024 * 1024;

    size_t maxHeaderSize = DEFAULT_MAX_HEADER_SIZE;
    size_t maxHeaderNum = DEFAULT_MAX_HEADER_NUM;
    size_t maxBodySize = DEFAULT_MAX_BODY_SIZE;

    explicit HttpObjectDecoder() noexcept = default;
    NO_COPY(HttpObjectDecoder)
};


class HttpRequestDecoder: public HttpObjectDecoder<HttpRequest, HTTP_REQUEST>
{
    StringRef mPath;
    StringRef mMethod;

    int on_url(const char *at, size_t length) noexcept {
        updateString(mPath, at, length);
        return 0;
    }

    int on_method(const char *at, size_t len) noexcept {
        updateString(mMethod, at, len);
        return 0;
    }

protected:
    void initParser() noexcept override {
        HttpObjectDecoder::initParser();

        mSettings.on_method = [](llhttp_t *parser, const char *at, size_t len) noexcept -> int  {
            auto self = static_cast<HttpRequestDecoder*>(parser->data);
            return self->on_method(at, len);
        };
        mSettings.on_url = [](llhttp_t *parser, const char *at, size_t len) noexcept -> int  {
            auto self = static_cast<HttpRequestDecoder*>(parser->data);
            return self->on_url(at, len);
        };
    }

    void updateHttpObject(HttpRequest &httpObject) noexcept override {
        HttpObjectDecoder::updateHttpObject(httpObject);
        std::swap(mPath, httpObject.mPath);
        std::swap(mMethod, httpObject.mMethod);
    }

public:
    explicit HttpRequestDecoder() noexcept = default;
    NO_COPY(HttpRequestDecoder)
};

class HttpResponseDecoder: public HttpObjectDecoder<HttpResponse, HTTP_RESPONSE>
{
    StringRef mMessage;

    int on_status(const char *at, size_t length) noexcept {
        updateString(mMessage, at, length);
        return 0;
    }

protected:
    void initParser() noexcept override {
        HttpObjectDecoder::initParser();
        mSettings.on_status = [](llhttp_t *parser, const char *at, size_t length) -> int {
            auto self = static_cast<HttpResponseDecoder*>(parser->data);
            return self->on_status(at, length);
        };
    }

    void updateHttpObject(hysburg::HttpResponse &httpObject) noexcept override {
        HttpObjectDecoder::updateHttpObject(httpObject);
        std::swap(httpObject.mMessage, mMessage);
    }
};

template <typename HttpObjectType>
class HttpObjectEncoder: public MessageToByteEncoder<HttpObjectType>
{
protected:
    void encode(ChannelHandlerContext &ctx, HttpObjectType &msg, ByteBuf &out) noexcept override
    {
        auto body = msg.body();
        auto expectedContentLength = std::to_string(body.length());
        auto actuallyContentLength = msg.header("content-length");

        if (expectedContentLength != actuallyContentLength) {
            msg.header("content-length", expectedContentLength);
        }
        for (const auto &it : msg.headers()) {
            out.writeBytes(it.first);
            out.writeBytes(": ");
            out.writeBytes(it.second);
            out.writeBytes("\r\n");
        }
        out.writeBytes("\r\n");
        out.writeBytes(body.data(), body.length());
    }
};


class HttpRequestEncoder: public HttpObjectEncoder<HttpRequest>
{
protected:
    void encode(ChannelHandlerContext &ctx, HttpRequest &msg, ByteBuf &out) noexcept override {
        out.writeBytes(msg.method());
        out.writeBytes(" ");
        out.writeBytes(msg.path());
        out.writeBytes(" HTTP/1.1\r\n");
        HttpObjectEncoder::encode(ctx, msg, out);
    }
};

class HttpResponseEncoder: public HttpObjectEncoder<HttpResponse>
{
protected:
    void encode(hysburg::ChannelHandlerContext &ctx, hysburg::HttpResponse &msg, hysburg::ByteBuf &out) noexcept override {
        out.writeBytes("HTTP/1.1 ");
        out.writeBytes(std::to_string(msg.code()));
        out.writeBytes(" ");
        out.writeBytes(msg.message());
        out.writeBytes(" \r\n");
        HttpObjectEncoder::encode(ctx, msg, out);
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