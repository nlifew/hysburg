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
    template <typename, llhttp_type_t>
    friend class HttpObjectDecoder;

protected:
    static constexpr size_t INVALID_OFFSET = (size_t) -1;

    struct StringRef {
        size_t off = INVALID_OFFSET;
        size_t len = 0;
        size_t cap = 0;

        [[nodiscard]]
        std::string_view get(const ByteBuf &buf) const {
            return off == INVALID_OFFSET ?
                std::string_view {  } :
                std::string_view { (const char*) buf.data() + off, len };
        }
    };

    static void trimKey(const StringRef &str, ByteBuf &buf) {
        trimKey(str, (char*) buf.data());
    }
    static void trimKey(const StringRef &str, char *buf) {
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

    void update(StringRef *dest, const std::string_view &src) {
        // 检查空间是否足够
        if (dest->cap >= src.size()) {
            // 备份当前 wIndex
            auto wIndex = mRaw.writeIndex();
            // 移动指针，跳转到 oldValue 的位置
            mRaw.writeIndex(dest->off);
            // 写入字符串
            mRaw.writeBytes(src);
            // 还原 wIndex
            mRaw.writeIndex(wIndex);
            // 更新数据
            dest->len = src.size();
            return;
        }
        // 直接在后面插入
        auto wIndex = mRaw.writeIndex();
        mRaw.writeBytes(src);
        dest->off = wIndex;
        dest->len = src.size();
        dest->cap = src.size();
    }
public:
    virtual ~HttpObject() = default;

    std::string_view header(const std::string_view &name) {
        auto it = std::find_if(
                mHeaders.begin(),
                mHeaders.end(),
                [&name, this](Header &it) -> bool {
                    return name == it.first.get(mRaw);
                }
        );
        if (it == mHeaders.end()) {
            return "";
        }
        return it->second.get(mRaw);
    }

    auto headers() {
        std::vector<std::pair<std::string_view, std::string_view>> vec(mHeaders.size());
        for (size_t i = 0; i < mHeaders.size(); i ++) {
            auto &header = mHeaders[i];
            vec[i] = std::make_pair(
                    header.first.get(mRaw),
                    header.second.get(mRaw)
            );
        }
        return vec;
    }

    HttpObject &header(const std::string_view &name, const std::string_view &value) {
        auto it = std::find_if(
                mHeaders.begin(),
                mHeaders.end(),
                [&name, this](Header &it) -> bool {
                    return name == it.first.get(mRaw);
                }
        );
        if (it != mHeaders.end()) {
            update(&it->second, value);
            return *this;
        }
        StringRef newName;
        update(&newName, name);
        trimKey(newName, mRaw);

        StringRef newValue;
        update(&newValue, value);
        mHeaders.emplace_back(newName, newValue);
        return *this;
    }

    [[nodiscard]]
    bool isSuccess() const { return mSuccess; }

    std::string_view body() { return mBody.get(mRaw); }

    HttpObject &body(const std::string_view &newBody) {
        update(&mBody, newBody);
        return *this;
    }
};

class HttpRequest: public HttpObject
{
private:
    friend class HttpRequestDecoder;
    StringRef mPath;
    StringRef mMethod;
public:
    HttpRequest &path(const std::string_view &newPath) {
        update(&mPath, newPath);
        return *this;
    }

    HttpRequest &method(const std::string_view &newMethod) {
        update(&mMethod, newMethod);
        return *this;
    }

    std::string_view path() { return mPath.get(mRaw); }
    std::string_view method() { return mMethod.get(mRaw); }

    explicit HttpRequest() = default;
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
    explicit HttpResponse() {
        message("OK");
    }

    [[nodiscard]]
    std::string_view message() const { return getMessageByCode(mCode); }

    static std::string_view getMessageByCode(HttpCode code) {
        return llhttp_status_name(code);
    }

    [[nodiscard]]
    HttpCode code() const { return mCode; }

    HttpResponse &code(HttpCode newCode) {
        mCode = newCode;
        return *this;
    }

    [[nodiscard]]
    std::string_view message() { return mMessage.get(mRaw); }

    HttpResponse &message(const std::string_view &newMessage) {
        update(&mMessage, newMessage);
        return *this;
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

    size_t offsetOfData(const char *at) const {
        assert(mData != nullptr);
        return at - mData;
    }

    void updateString(StringRef *out, const char *at, size_t length) const {
        auto offset = offsetOfData(at);
        // 可能读到不完整的片段
        if (out->off == INVALID_OFFSET) {
            out->off = offset;
            out->len = length;
        } else {
            CHECK(out->off + out->len == offset,
                  "wtf, out->off='%zu', out->len='%zu', offset='%zu'",
                  out->off, out->len, offset
            )
            out->len += length;
        }
        out->cap = out->len;
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
    int on_message_begin() {
        mCurHeaderName = {};
        mCurHeaderValue = {};
        mBody = {};
        mHeaders.clear();
        assert(mData != nullptr);
        return 0;
    }

    int on_header_field(const char *at, size_t length) {
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
        updateString(&mCurHeaderName, at, length);
        return 0;
    }

    int on_header_value(const char *at, size_t length) {
        if (!mHeaders.empty()) {
            size_t offset = offsetOfData(at);
            auto firstOffset = mHeaders[0].first.off;
            if (offset - firstOffset + length > maxHeaderSize) {
                llhttp_set_error_reason(&mHttpParser, "access max header size");
                return -1;
            }
        }
        updateString(&mCurHeaderValue, at, length);
        return 0;
    }

    /**
     * 把当前 header 提交到 vector
     */
    int on_header_value_complete() {
        mHeaders.emplace_back(mCurHeaderName, mCurHeaderValue);
        mCurHeaderName = {};
        mCurHeaderValue = {};
        return 0;
    }

    int on_headers_complete() {
        if (mHttpParser.content_length > maxBodySize) {
            llhttp_set_error_reason(&mHttpParser, "access max body size");
            return -1;
        }
        for (auto &it : mHeaders) {
            HttpObject::trimKey(it.first, mData);
        }
        if (llhttp_get_upgrade(&mHttpParser)) {
            return 2; // 2 会使 llhttp_execute() 返回 HPE_PAUSED_UPGRADE
        }
        return 0;
    }

    int on_body(const char *at, size_t length) {
        updateString(&mBody, at, length);
        return 0;
    }

    /**
     * 当 http 消息解析完成的时候立即暂停 [HPE_PAUSED]，用来在 [llhttp_execute] 中快速返回。
     * 返回 HPE_PAUSED 的原因有以下几点：
     * 1. 消息可能有粘连，即一个 ByteBuf 中含有多个 http 请求。我们需要在解析完一个的时候及时暂停
     * 2. 得知当前解析器的 cursor 在哪 [llhttp_get_error_pos]，用来调整 ByteBuf 的指针
     */
    int on_message_complete() {
        if (llhttp_get_upgrade(&mHttpParser)) {
            return HPE_OK;
        }
        return HPE_PAUSED;
    }

    void initSettings() {
        llhttp_settings_init(&mSettings);
#define XX(NAME) \
        mSettings.NAME = [](llhttp_t *parser) -> int { \
            auto self = static_cast<HttpObjectDecoder*>(parser->data); \
            return self->NAME(); \
        };
        XX(on_message_begin)
        XX(on_message_complete)
        XX(on_header_value_complete)
        XX(on_headers_complete)
#undef XX

#define XX(NAME) \
        mSettings.NAME = [](llhttp_t *parser, const char *at, size_t length) -> int { \
            auto self = static_cast<HttpObjectDecoder*>(parser->data); \
            return self->NAME(at, length); \
        };
        XX(on_header_field)
        XX(on_header_value)
        XX(on_body)
#undef XX
    }

    llhttp_errno_t decode0(ChannelHandlerContext &ctx, ByteBuf &in) {
        if (in.readableBytes() > maxBuffSize) {
            return HPE_USER;
        }
        // mData 指向数据开始的指针
        mData = (char *) in.readData();
        auto err = llhttp_execute(
                &mHttpParser,
                mData + mLastDecodedBytes, // [1]
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

    void complete0(ByteBuf &byteBuf, std::vector<AnyPtr> &out) {
        // 现在指针的位置
        auto pos = llhttp_get_error_pos(&mHttpParser);
        // 整个对象的大小
        size_t httpObjectSize = pos - (char *) byteBuf.readData();

        // 把当前 byteBuf 拆分：pos 及之前的内容给 httpObject，之后的部分继续保留
        auto httpObjectMsg = makeAny<HttpObjectType>();
        auto httpObject = httpObjectMsg->template as<HttpObjectType>();
        if (byteBuf.readableBytes() == httpObjectSize) {
            httpObject->mRaw.clear();
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

    virtual void initParser() {
        initSettings();
        llhttp_init(&mHttpParser, HttpParserType, &mSettings);
        llhttp_set_lenient_optional_cr_before_lf(&mHttpParser, 1);
        mHttpParser.data = this;
    }

    virtual void updateHttpObject(HttpObjectType &httpObject) {
        std::swap(httpObject.mHeaders, mHeaders);
        std::swap(httpObject.mBody, mBody);
    }
public: // visible for test

    void decode(ChannelHandlerContext &ctx, ByteBuf &in, std::vector<AnyPtr> &out) override {
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
    static constexpr size_t DEFAULT_MAX_HEADER_NUM = 64;
    static constexpr size_t DEFAULT_MAX_HEADER_SIZE = 32 * 1024;
    static constexpr size_t DEFAULT_MAX_BODY_SIZE = 512 * 1024;
    static constexpr size_t DEFAULT_MAX_BUFF_SIZE = 2 * 1024 * 1024;

    size_t maxHeaderSize = DEFAULT_MAX_HEADER_SIZE;
    size_t maxHeaderNum = DEFAULT_MAX_HEADER_NUM;
    size_t maxBodySize = DEFAULT_MAX_BODY_SIZE;
    size_t maxBuffSize = DEFAULT_MAX_BUFF_SIZE;

    explicit HttpObjectDecoder() = default;
    NO_COPY(HttpObjectDecoder)
};


class HttpRequestDecoder: public HttpObjectDecoder<HttpRequest, HTTP_REQUEST>
{
    StringRef mPath;
    StringRef mMethod;

    int on_url(const char *at, size_t length) {
        updateString(&mPath, at, length);
        return 0;
    }

    int on_method(const char *at, size_t len) {
        updateString(&mMethod, at, len);
        return 0;
    }

protected:
    void initParser() override {
        HttpObjectDecoder::initParser();

        mSettings.on_method = [](llhttp_t *parser, const char *at, size_t len) -> int  {
            auto self = static_cast<HttpRequestDecoder*>(parser->data);
            return self->on_method(at, len);
        };
        mSettings.on_url = [](llhttp_t *parser, const char *at, size_t len) -> int  {
            auto self = static_cast<HttpRequestDecoder*>(parser->data);
            return self->on_url(at, len);
        };
    }

    void updateHttpObject(HttpRequest &httpObject) override {
        HttpObjectDecoder::updateHttpObject(httpObject);
        std::swap(mPath, httpObject.mPath);
        std::swap(mMethod, httpObject.mMethod);
    }

public:
    explicit HttpRequestDecoder() = default;
    NO_COPY(HttpRequestDecoder)
};

class HttpResponseDecoder: public HttpObjectDecoder<HttpResponse, HTTP_RESPONSE>
{
    StringRef mMessage;

    int on_status(const char *at, size_t length) {
        updateString(&mMessage, at, length);
        return 0;
    }

protected:
    void initParser() override {
        HttpObjectDecoder::initParser();
        mSettings.on_status = [](llhttp_t *parser, const char *at, size_t length) -> int {
            auto self = static_cast<HttpResponseDecoder*>(parser->data);
            return self->on_status(at, length);
        };
    }

    void updateHttpObject(HttpResponse &httpObject) override {
        HttpObjectDecoder::updateHttpObject(httpObject);
        std::swap(mMessage, httpObject.mMessage);
    }
public:
    explicit HttpResponseDecoder() = default;
    NO_COPY(HttpResponseDecoder)
};

template <typename HttpObjectType>
class HttpObjectEncoder: public MessageToByteEncoder<HttpObjectType>
{
protected:
    virtual void fixHttpObject(HttpObjectType &msg) {
        // 修复 content-length
        auto body = msg.body();
        auto expectedContentLength = std::to_string(body.length());
        auto actuallyContentLength = msg.header("content-length");

        if (expectedContentLength != actuallyContentLength) {
            msg.header("content-length", expectedContentLength);
        }
    }

    void encode(ChannelHandlerContext &ctx, HttpObjectType &msg, ByteBuf &out) override
    {
        // 修复一些不正确的状态
        fixHttpObject(msg);

        for (const auto &it : msg.headers()) {
            out.writeBytes(it.first);
            out.writeBytes(": ");
            out.writeBytes(it.second);
            out.writeBytes("\r\n");
        }
        out.writeBytes("\r\n");
        out.writeBytes(msg.body().data(), msg.body().length());
    }
};


class HttpRequestEncoder: public HttpObjectEncoder<HttpRequest>
{
protected:
    void fixHttpObject(HttpRequest &msg) override {
        HttpObjectEncoder::fixHttpObject(msg);
        if (msg.path().empty()) {
            msg.path("/");
        }
        if (msg.method().empty()) {
            msg.method("GET");
        }
    }

    void encode(ChannelHandlerContext &ctx, HttpRequest &msg, ByteBuf &out) override {
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
    void encode(hysburg::ChannelHandlerContext &ctx, hysburg::HttpResponse &msg, hysburg::ByteBuf &out) override {
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
    explicit HttpClientCodec() {
        init(std::make_shared<HttpResponseDecoder>(), std::make_shared<HttpRequestEncoder>());
    }
    NO_COPY(HttpClientCodec)
};

class HttpServerCodec: public CombinedChannelDuplexHandler
{
public:
    explicit HttpServerCodec() {
        init(std::make_shared<HttpRequestDecoder>(), std::make_shared<HttpResponseEncoder>());
    }
    NO_COPY(HttpServerCodec)
};

}


#endif // HYSBURG_CHANNEL_HTTP_OBJECT