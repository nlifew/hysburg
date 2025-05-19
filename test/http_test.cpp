
#include "channel/HttpObject.hpp"
#include "channel/UVSocketChannel.hpp"

using namespace hysburg;

static std::string toString(HttpRequest &http) {
    std::string str;
    str.append(http.method()).append(" ").append(http.path()).append(" HTTP/1.1\n");
    for (const auto &header : http.headers()) {
        str.append(header.first).append(": ").append(header.second).append("\n");
    }
    str.append("\n");
    str.append(http.body());
    return str;
}

static std::string toString(ByteBuf &byteBuf) {
    std::string str;
    str.assign((char*) byteBuf.readData(), byteBuf.readableBytes());
    return str;
}

static std::string toString(Any &any) {
    if (any.is<ByteBuf>()) {
        return toString(*any.as<ByteBuf>());
    }
    if (any.is<HttpRequest>()) {
        return toString(*any.as<HttpRequest>());
    }
    assert(0);
}

static void test(
        ChannelHandlerContext &ctx,
        HttpRequestDecoder &decoder,
        const std::vector<std::string>& vec
) {
    ByteBuf byteBuf;
    std::vector<AnyPtr> out;

    for (auto &it : vec) {
        byteBuf.writeBytes(it);
        decoder.decode(ctx, byteBuf, out);
    }
    auto failed = std::find_if(out.begin(), out.end(), [](AnyPtr &it) -> bool {
        auto http = it->is<HttpRequest>();
        return http && !http->isSuccess();
    });
    assert(!out.empty() && failed == out.end());
    for (auto &it : out) {
        printf("--------------------------------------------------------\n");
        printf("%s", toString(*it).c_str());
    }
}

int main() {
    UVSocketChannel channel;
    ChannelHandlerContext ctx(&channel);
    HttpRequestDecoder decoder;

//    // 正常情况
//    test(ctx, decoder, {
//        "GET / HTTP/1.1\r\n"
//        "Content-Length: 5\r\n"
//        "\r\n"
//        "12345"
//    });
//    // 按行拆包
//    test(ctx, decoder, {
//            "GET / HTTP/1.1\r\n",
//            "Content-Length: 5\r\n",
//            "\r\n",
//            "12345",
//    });
//    // 不规则拆包
//    test(ctx, decoder, {
//        "GET / ", "HTTP/1.1\r\n",
//        "Content-Length", ": ", "5\r\n",
//        "\r\n",
//        "123", "45"
//    });
//    // 多个 http 请求
//    test(ctx, decoder, {
//        "GET / HTTP/1.1\r\n",
//        "Content-Length: 5\r\n",
//        "\r\n",
//        "12345POST /post HTTP/1.1\r\n",
//        "XX: second\r\n"
//    });
    // upgrade
    test(ctx, decoder, {
        "GET / HTTP/1.1\r\n",
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n",
        "\r\n",
        "hello"
    });
}