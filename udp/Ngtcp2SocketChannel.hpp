
#ifndef HYSBURG_NGTCP2_SOCKET_CHANNEL_HPP
#define HYSBURG_NGTCP2_SOCKET_CHANNEL_HPP

#include <openssl/rand.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include "Util.hpp"
#include "channel/EventLoop.hpp"
#include "channel/Channel.hpp"

namespace hysburg {

namespace internal {

    static constexpr int MAX_UDP_PAYLOAD_SIZE = 1450;
    static constexpr int MAX_UDP_BATCH_NUM = 64;

    struct UdpPacket {
        uint8_t data[MAX_UDP_PAYLOAD_SIZE];
        size_t size;
    };

    class WriteHelper {
        uint64_t quantum = 0;
        ngtcp2_conn *conn = nullptr;
        std::array<UdpPacket, MAX_UDP_BATCH_NUM> packets;
        size_t packetsLen = 0;
        bool hasAnythingSent = false;
    public:
        uint64_t ts = 0;

        explicit WriteHelper(ngtcp2_conn *conn, uint64_t ts) { // NOLINT(*-pro-type-member-init)
            this->conn = conn;
            this->ts = ts;
            this->quantum = ngtcp2_conn_get_send_quantum(conn);
        }

        NO_COPY(WriteHelper)

        ~WriteHelper() {
            CHECK(packetsLen == 0, "remaining data !")
            if (hasAnythingSent) {
                ngtcp2_conn_update_pkt_tx_time(conn, ts);
            }
        }

        uint8_t *buffer() { return packets[packetsLen].data; }
        size_t bufferSize() { (void) this; return MAX_UDP_PAYLOAD_SIZE; }

        /**
         * 尝试发送 bytes 个字节。配额消耗完或者 udp 发送失败时会返回负数，
         * 此时应该尽快退出循环
         * bytes 为 0 表示强制刷新，此时并不会真正发出去一个空包
         */
        int write(uv_udp_t *udp, size_t bytes) {
            auto ret = 0;
            if (bytes > 0) {
                packets[packetsLen ++].size = bytes;
            }
            // 消耗掉配额
            if (bytes >= quantum) {
                quantum = 0;
                ret = -1;
            } else {
                quantum -= bytes;
            }
            // 真正的刷新逻辑
            if ((bytes == 0 && packetsLen > 0) || packetsLen == packets.size()) {
                std::array<uv_buf_t, MAX_UDP_BATCH_NUM> buf;        // NOLINT(*-pro-type-member-init)
                std::array<uv_buf_t*, MAX_UDP_BATCH_NUM> bufs;      // NOLINT(*-pro-type-member-init)
                std::array<unsigned int, MAX_UDP_BATCH_NUM> bufNs;  // NOLINT(*-pro-type-member-init)
                std::array<sockaddr*, MAX_UDP_BATCH_NUM> addrs {};

                for (size_t i = 0, z = packetsLen; i < z; i ++) {
                    auto &packet = packets[i];
                    buf[i] = {
                            .base = reinterpret_cast<char*>(packet.data),
                            .len = packet.size,
                    };
                    bufs[i] = &buf[i];
                    bufNs[i] = 1;
                }
                auto n = uv_udp_try_send2(
                        udp, packetsLen,
                        bufs.data(), bufNs.data(), addrs.data(),
                        0
                );
                // TODO 这里需要更好的错误处理方式，不应该直接丢弃
                if (n < 0 || static_cast<size_t>(n) < packetsLen) {
                    ret = -1;
                }
                packetsLen = 0;
                hasAnythingSent = true;
            }
            return ret;
        }
    };

    class UvCloser {
        int mRefCount = 0;
        void *mData = nullptr;
        void (*mCloseFn)(void*) = nullptr;

    public:
        explicit UvCloser() = default;
        NO_COPY(UvCloser)

        ~UvCloser() {
            CHECK(mRefCount == 0, "invalid state")
        }

        template<typename T>
        void reset(T *data, void(*fn)(T *)) {
            mData = data;
            mCloseFn = reinterpret_cast<void(*)(void*)>(fn);
            mRefCount = 0;
        }

        void close(uv_handle_t *handle) {
            mRefCount += 1;
            handle->data = this;
            uv_close(handle, [](uv_handle_t *handle) {
                auto self = static_cast<UvCloser*>(handle->data);
                if ((self->mRefCount -= 1) == 0 && self->mCloseFn != nullptr) {
                    auto fn = self->mCloseFn;
                    self->mCloseFn = nullptr;
                    fn(self->mData);
                }
            });
        }
    };
}

enum Ngtcp2ChannelOption {
};

enum class StreamMsgType {
    OPEN, CLOSE, WRITE, FLUSH,
};

struct StreamMsg {
    StreamMsgType type;
    int64_t streamId;
    ByteBuf byteBuf;
};

class Ngtcp2SocketChannel: public Channel {
public:
    using WriteHelper = internal::WriteHelper;

    /**
     * UDP 相关
     */
    uv_udp_t mUdp {};
    uv_timer_t mTimer {};
    internal::UvCloser mUvCloser;


    /**
     * QUIC 相关
     */
    ngtcp2_conn *mConn = nullptr;
    ngtcp2_path mPath {};
    ngtcp2_cid mScid {}, mDicd {};
    ngtcp2_crypto_conn_ref mConnRef {};
    ngtcp2_ccerr mCCError {};

    ngtcp2_settings mSettings {};
    ngtcp2_callbacks mCallbacks {};
    ngtcp2_transport_params mParams {};

    /**
     * SSL 相关
     */
    SSL_CTX *mSSLCtx = nullptr; // 并不拥有 SSL_CTX 的所有权
    std::unique_ptr<SSL, decltype(&SSL_free)> mSSL { nullptr, SSL_free};
    std::vector<uint8_t> mAlpn;

    /**
     * stream 管理
     */
    struct WriteOnce {
        ByteBuf byteBuf;
        PromisePtr<void> promise;
        size_t originalSize = 0; // msg 的原始字节数
    };

    struct Stream {
        int64_t id = UINT64_MAX;
        Stream *next = nullptr;

        // TODO 下面这俩考虑换成环形队列
        // TODO mPending 放在 Stream 维度可能会产生公平问题。即数据包的发送顺序完全依赖于 Stream 的遍历顺序
        std::vector<WriteOnce> mPending; // 还没有执行 flush 写入的
        std::vector<WriteOnce> mWriting; // 对端还没有确认的
    };
    std::map<int64_t, Stream> mStreamMap;
    Stream *mActiveStreamHead = nullptr;
    Stream *mActiveStreamTail = nullptr;

    void initSettings() {
        ngtcp2_settings_default(&mSettings);
        mSettings.cc_algo = ngtcp2_cc_algo::NGTCP2_CC_ALGO_BBR;
        mSettings.initial_ts = uv_hrtime();
        mSettings.handshake_timeout = 10000000000; // 10s
    }

    void initParams() {
        ngtcp2_transport_params_default(&mParams);
        mParams.initial_max_data = 10 * 1024 * 1024;
        mParams.initial_max_stream_data_bidi_local = 1 * 1024 * 1024;
        mParams.initial_max_stream_data_bidi_remote = 1 * 1024 * 1024;
        mParams.initial_max_streams_bidi = UINT32_MAX;
        mParams.grease_quic_bit = 1;
        mParams.max_udp_payload_size = internal::MAX_UDP_PAYLOAD_SIZE;
    }

    void initCallback() {
#define ADD3(X, Y, Z) X##Y##Z
#define X(NAME) mCallbacks.NAME = ADD3(::ngtcp2_crypto_, NAME, _cb)
        X(client_initial);
        X(recv_crypto_data);
        X(encrypt);
        X(decrypt);
        X(hp_mask);
        X(recv_retry);
        X(update_key);
        X(delete_crypto_aead_ctx);
        X(delete_crypto_cipher_ctx);
        X(get_path_challenge_data);
        X(version_negotiation);
#undef X
#undef ADD3
        mCallbacks.rand = [](uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *) {
            RAND_bytes(dest, destlen);
        };
        mCallbacks.get_new_connection_id = [](ngtcp2_conn *, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *) -> int {
            cid->datalen = cidlen;
            RAND_bytes(cid->data, cidlen);
            RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
            return 0;
        };
        mCallbacks.handshake_confirmed = [](ngtcp2_conn *, void *user_data) -> int {
            LOGD("handshake confirmed");
            auto self = static_cast<Ngtcp2SocketChannel*>(user_data);
            ngtcp2_ccerr_set_application_error(&self->mCCError, 0, nullptr, 0);

            self->mPipeline.fireChannelActive();
            setResult(true, self->mConnectPromise);
            return 0;
        };
        // TODO 这里监听 stream 相关事件
    }

    void doRegister() override {
        mTimer.data = this;
        uv_timer_init(mExecutor->handle(), &mTimer);

        mUdp.data = this;
        uv_udp_init_ex(mExecutor->handle(), &mUdp, UV_UDP_RECVMMSG | AF_UNSPEC);

        initCallback();
        initSettings();
        initParams();

        mPipeline.addAllHandlers(mExecutor);
        setResult(true, mRegisterPromise);
    }

    void doBind() override {
        auto ret = uv_udp_bind(&mUdp, &mLocalAddress.addr, 0);
        setResult(ret == 0, mBindPromise);
    }

    int sslConnect() {
        if (mSSLCtx == nullptr) {
            return -1;
        }
        if (ngtcp2_crypto_boringssl_configure_client_context(mSSLCtx) != 0) {
            return -2;
        }
        auto ssl = SSL_new(mSSLCtx);
        if (ssl == nullptr) {
            return -3;
        }
        mSSL.reset(ssl);
        SSL_set_connect_state(ssl);
        SSL_set_app_data(ssl, &mConnRef);
        SSL_set_alpn_protos(ssl, mAlpn.data(), mAlpn.size());
        SSL_set1_host(ssl, mConnectHost.c_str());
        SSL_set_tlsext_host_name(ssl, mConnectHost.c_str());
        mConnRef = {
                .get_conn = [](ngtcp2_crypto_conn_ref *conn_ref) -> ngtcp2_conn* {
                    return static_cast<Ngtcp2SocketChannel*>(conn_ref->user_data)->mConn;
                },
                .user_data = this,
        };
        return 0;
    }

    int udpConnect() {
        // 提前 connect 一次，拿到准确的 localAddress。
        // connect 对 udp client 确实很有好处，之后 udp socket 就只能收到来自这个地址的 udp 包了
        // 不过由于存在微小的时间差，uv_udp_recv_start() 确实有可能收到来自其他地址的 udp 包。
        auto ret = uv_udp_connect(&mUdp, &mRemoteAddress.addr);
        if (ret != 0) {
            return ret;
        }

        int localSockLen = sizeof(mLocalAddress);
        ret = uv_udp_getsockname(&mUdp, &mLocalAddress.addr, &localSockLen);
        if (ret != 0) {
            return ret;
        }
        // 初始化 udp 收消息逻辑
        // 这里不太合适，给 libuv 分配了 128kb 内存，它只会切分成 2 个 iovec，
        // 同时读取 2 个udp 数据包（为了保证数据不截断，使用了最安全的 64kb 大小）
        // TODO 考虑替换掉 libuv 的 udp 实现
        ret = uv_udp_recv_start(&mUdp, [](uv_handle_t *handle, size_t suggested_size, uv_buf_t* buf) {
            auto isRecvMmsg = uv_udp_using_recvmmsg(reinterpret_cast<uv_udp_t*>(handle));
            buf->len = isRecvMmsg ? (suggested_size * 2) : suggested_size;
            auto ptr = ByteBuf::Allocator().alloc(buf->len);
            buf->base = reinterpret_cast<char *>(ptr);
        }, [](uv_udp_t *handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr *addr, unsigned flags) {
            auto ptr = reinterpret_cast<uint8_t*>(buf->base);
            if (nread > 0 && addr != nullptr) {
                auto self = static_cast<Ngtcp2SocketChannel*>(handle->data);
                self->onReceiveUdpPackets({ ptr,  (size_t) nread }, addr);
            }
            if ((flags & UV_UDP_MMSG_CHUNK) == 0) {
                ByteBuf::Allocator().free(ptr);
            }
        });
        return ret;
    }

    ngtcp2_path *ngtcp2Path() {
        mPath = {
                .local = { .addr = &mLocalAddress.addr, .addrlen = Net::getSockLen(mLocalAddress.addr.sa_family) },
                .remote = { .addr = &mRemoteAddress.addr, .addrlen = Net::getSockLen(mRemoteAddress.addr.sa_family) },
                .user_data = nullptr,
        };
        return reinterpret_cast<ngtcp2_path*>(&mPath);
    }

    int ngtcp2Connect() {
        mScid.datalen = mDicd.datalen = NGTCP2_MAX_CIDLEN;
        RAND_bytes(mScid.data, NGTCP2_MAX_CIDLEN);
        RAND_bytes(mDicd.data, NGTCP2_MAX_CIDLEN);

        ngtcp2_ccerr_set_transport_error(&mCCError, 1, nullptr, 0);

        return ngtcp2_conn_client_new(
                &mConn, &mDicd, &mScid,
                ngtcp2Path(),
                NGTCP2_PROTO_VER_V1,
                &mCallbacks, &mSettings, &mParams,
                ngtcp2_mem_default(), this
        );
    }

    void doConnect() override {
        // 想了一下还是吧 ngtcp2_conn 的初始化放在最后面
        // 只要这个 conn 为 nullptr 就说明没有 connect 完成。
        // 当然了，先初始化 udpSocket 可能造成 conn 为 nullptr 时就提前收到 udp 包的问题。
        // 大多数情况下不会发生，因为 libuv 的回调会在下一个事件循环里调用，而我们在当前事件循环里就把 conn 初始化好了。
        // 少部分情况下，conn 初始化失败，确实有这个可能。所以要在 onReceiveUdpPackets() 里加上判断
        if (sslConnect() != 0 || udpConnect() != 0 || ngtcp2Connect() != 0) {
            setResult(false, mConnectPromise);
            return;
        }
        ngtcp2_conn_set_tls_native_handle(mConn, mSSL.get());
        {
            WriteHelper helper(mConn, uv_hrtime());
            writeEmptyAndFlush(helper);
        }
        updateTimer();
    }

    void onReceiveUdpPackets(std::span<uint8_t> packet, const sockaddr *addr) {
        // 必须要做一个检查，udp 初始化早于 conn，销毁晚于 conn
        if (mConn == nullptr) {
            return;
        }
        // 注意 addr 并不一定就等于 mRemoteAddress。因为在 udp connect 之前，
        // 内核并不会过滤掉其他地址的 udp 包。udp socket 在初始化到 connect 之间肯定有时间间隔的
        // 考虑到服务器地址不会改变，这里简单做一下过滤
        if (!Net::equals(&mRemoteAddress.storage, addr)) {
            return;
        }
        const auto ts = uv_hrtime();
        // TODO 增加 ecn 支持
        auto ret = ngtcp2_conn_read_pkt(
                mConn, ngtcp2Path(), nullptr, packet.data(), packet.size(), ts
        );
        switch (ret) {
            // 链接即将消亡或者已经发送过 close 帧，不需要任何处理
            case NGTCP2_NO_ERROR: {
                WriteHelper helper(mConn, ts);
                writeEmptyAndFlush(helper);
                [[fallthrough]];
            }
            case NGTCP2_ERR_DRAINING:
            case NGTCP2_ERR_CLOSING:
                updateTimer();
                return;
        }
        // 走到这里说明发生了异常
        if (ret == NGTCP2_ERR_CRYPTO) {
            ngtcp2_ccerr_set_tls_alert(
                    &mCCError, ngtcp2_conn_get_tls_alert(mConn), nullptr, 0
            );
        }
        // 如果是握手期间的异常，直接通知给上层
        if (!ngtcp2_conn_get_handshake_completed(mConn)) {
            setResult(false, mConnectPromise);
            return;
        }
        // 直接关掉好了
        doClose();
    }

    void doOption(int key, void *value) override {
        (void) key; // TODO
        (void) value;
    }

    Stream *findStreamById(int64_t id) {
        auto it = mStreamMap.find(id);
        return it == mStreamMap.end() ? nullptr : &it->second;
    }

    void doWrite(AnyPtr msg, PromisePtr<void> promise) override {
        auto *streamMsg = msg->is<StreamMsg>();
        if (UNLIKELY(streamMsg == nullptr)) {
            LOGW("unknown msg type: '%s'", msg->type.name());
            setResult(false, promise);
            return;
        }
        // 先把数据写入到缓冲区，等待统一刷新
        auto *stream = findStreamById(streamMsg->streamId);
        if (UNLIKELY(stream == nullptr)) {
            LOGW("stream '%lld' not found", streamMsg->streamId);
            setResult(false, promise);
            return;
        }
        auto &once = stream->mPending.emplace_back();
        once.byteBuf.swap(streamMsg->byteBuf);
        once.promise.swap(promise);
        once.originalSize = once.byteBuf.readableBytes();

        // 标记这个 Stream 为活跃状态
        if (stream->mPending.size() == 1) {
            if (mActiveStreamTail == nullptr) {
                mActiveStreamHead = stream;
            } else {
                mActiveStreamTail->next = stream;
            }
            mActiveStreamTail = stream;
        }
    }

    enum class FlushResult {
        /**
         * 一切正常
         */
        OK,

        /**
         * 触发 Stream 层级的流控，不应该继续写入当前 Stream
         */
        STOP_STREAM,

        /**
         * 触发了链接级别的流控，不应该继续写入当前链接
         */
        STOP_CONN,

        /**
         * 出现异常，应该调用 ngtcp2_conn_write_connection_close 关闭连接
         */
        CLOSE_CONN,
    };

    static FlushResult mapFlushResult(
            ngtcp2_ssize ret, std::span<ngtcp2_vec> vec
    ) {
        if (ret < 0) {
            switch (ret) {
                // 数据太小，不足以填满 udp 缓冲区
                case NGTCP2_ERR_WRITE_MORE:
                    return FlushResult::OK;
                // 因为流控等原因无法写入，但可以写入其他 stream
                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                case NGTCP2_ERR_STREAM_NOT_FOUND:
                case NGTCP2_ERR_STREAM_SHUT_WR:
                    return FlushResult::STOP_STREAM;
                // 正在关闭中（主动/被动），不能发送任何数据
                case NGTCP2_ERR_DRAINING:
                case NGTCP2_ERR_CLOSING:
                    return FlushResult::STOP_CONN;
                default:
                    return FlushResult::CLOSE_CONN;
            }
        }
        if (ret == 0) {
            // 需要检查是不是一个空数据包
            bool isEmpty = true;
            for (const auto &it : vec) {
                if (it.len > 0) {
                    isEmpty = false;
                    break;
                }
            }
            // 缓冲区太小不太可能。不为空时直接视为触发 cc
            if (!isEmpty) { return FlushResult::STOP_CONN; }
        }
        return FlushResult::OK;
    }


    /**
     * 生成一些纯控制帧
     */
    void writeEmptyAndFlush(WriteHelper &helper) {
        while (true) {
            auto ret = ngtcp2_conn_write_pkt(
                    mConn, nullptr, nullptr,
                    helper.buffer(), helper.bufferSize(), helper.ts
            );
            auto result = mapFlushResult(ret, {});
            if (result == FlushResult::CLOSE_CONN) {
                writeCloseAndFlush(helper);
                break;
            }
            if (ret == 0 || result == FlushResult::STOP_CONN) {
                break;
            }
            if (helper.write(&mUdp, ret) < 0) {
                break;
            }
        }
        helper.write(&mUdp, 0);
    }

    ngtcp2_ssize writeStreamAndFlush(
            Stream &stream, uint32_t flag, WriteHelper &helper, FlushResult *outResult
    ) {
        // TODO 增加对 ecn 的支持，即 ngtcp2_pkt_info

        // 准备 vec
        std::array<ngtcp2_vec, 64> vec; // NOLINT(*-pro-type-member-init)
        size_t vecLen = std::min(vec.size(), stream.mPending.size());
        for (size_t i = 0; i < vecLen; i ++) {
            auto &byteBuf = stream.mPending[i].byteBuf;
            vec[i] = {
                    .base = static_cast<uint8_t*>(byteBuf.readData()),
                    .len = byteBuf.readableBytes(),
            };
        }

        ngtcp2_ssize datalen = 0;
        auto ret = ngtcp2_conn_writev_stream(
                mConn, nullptr, nullptr,
                helper.buffer(), helper.bufferSize(),
                &datalen, flag, stream.id,
                vec.data(), vecLen, helper.ts
        );
        while (datalen > 0) {
            // 消耗掉明文
            auto &byteBuf = stream.mPending[0].byteBuf;
            auto consumed = std::min(byteBuf.readableBytes(), (size_t) datalen);
            byteBuf.offsetReader(consumed);
            if (byteBuf.readableBytes() == 0) {
                // 这个用完了，移动到 writing 队列等待对端确认
                WriteOnce tmp(std::move(stream.mPending[0]));
                stream.mPending.erase(stream.mPending.begin());
                stream.mWriting.emplace_back(std::move(tmp));
            }
            datalen -= consumed;
        }
        *outResult = mapFlushResult(ret, { vec.data(), vecLen });
        return ret;
    }

    /**
     * 从 mActiveStreamHead 开始沿着 next 指针遍历所有的活跃 stream
     */
    void writeStreamAndFlush(WriteHelper &helper) {
        // TODO 写入到 udp 缓冲区之后需要通知 promise。注意不要重入 ngtcp2

        for (Stream *stream; (stream = mActiveStreamHead) != nullptr;) {
            // 最后一个 stream 不能带 NGTCP2_WRITE_STREAM_FLAG_MORE，强制写入
            uint32_t flag = 0;
            if (stream != mActiveStreamTail) {
                flag |= NGTCP2_WRITE_STREAM_FLAG_MORE;
            }
            FlushResult result = FlushResult::OK;
            auto ret = writeStreamAndFlush(*stream, flag, helper, &result);

            if (result == FlushResult::CLOSE_CONN) {
                writeCloseAndFlush(helper);
                break;
            }
            if (result == FlushResult::STOP_CONN) {
                break;
            }
            if (result == FlushResult::STOP_STREAM || stream->mPending.empty()) {
                mActiveStreamHead = stream->next;
                stream->next = nullptr;
                if (mActiveStreamHead == nullptr) {
                    mActiveStreamTail = nullptr;
                }
            }
            if (helper.write(&mUdp, ret) < 0) {
                break;
            }
        }
        // 检查是否有需要发送的数据包
        helper.write(&mUdp, 0);
    }

    void writeCloseAndFlush(WriteHelper &helper) {
        auto ret = ngtcp2_conn_write_connection_close(
                mConn, nullptr, nullptr,
                helper.buffer(), helper.bufferSize(), &mCCError, helper.ts
        );
        // 可能因为各种原因无法发送 close 数据包。确实没有什么更好的办法
        if (ret <= 0) {
            return;
        }
        helper.write(&mUdp, ret);
    }

    void doFlush() override {
        {
            WriteHelper helper(mConn, uv_hrtime());
            writeStreamAndFlush(helper);
        }
        updateTimer();
    }

    void updateTimer() {
        uv_timer_stop(&mTimer);

        const auto now = uv_hrtime();
        auto ts = ngtcp2_conn_get_expiry(mConn);

        if (now > ts) {
            LOGD("next tick: expired '%lld' ms, reset to 0", (now - ts) / 1000000);
        } else {
            LOGD("next tick: '%lld' ms", (ts - now) / 1000000);
        }

        auto diff = now > ts ? 0 : (ts - now);

        if (ts != UINT64_MAX) {
            uv_timer_start(&mTimer, [](uv_timer_t *handle) {
                static_cast<Ngtcp2SocketChannel*>(handle->data)->onTimeout();
            }, diff / 1000000, 0);
        }
    }

    void onTimeout() {
        // 移除掉 timer，这样我们就能使用 uv_is_active() 判断定时器是否在运行了
        uv_timer_stop(&mTimer);

        auto ts = uv_hrtime();
        auto ret = ngtcp2_conn_handle_expiry(mConn, ts);
        switch (ret) {
            // 这个链接可以静默丢弃了
            case NGTCP2_ERR_IDLE_CLOSE:
                onConnClose();
                break;
            // 一切正常，调用 ngtcp2_conn_writev_stream() 发包并重置下次超时时间
            case NGTCP2_NO_ERROR: {
                WriteHelper helper(mConn, ts);
                writeEmptyAndFlush(helper);
                updateTimer();
                break;
            }
            // 握手超时. 此时链接处于关闭状态
            case NGTCP2_ERR_HANDSHAKE_TIMEOUT: {
                if (!mConnectPromise->retain().isDone()) {
                    setResult(false, mConnectPromise);
                } else {
                    doClose();
                }
                break; // 注意此时不能更新定时器，因为它的超时时间在过去
            }
            // 调用 ngtcp2_conn_write_connection_close() 发送 close 包
            default: {
                doClose();
                break;
            }
        }
    }

    void doListen(int) override {
        setResult(false, mListenPromise);
    }

    void doClose() override {
        // 这个应该比较好理解，从来没发出过 connect 请求，此时直接关闭即可
        if (mConn == nullptr) {
            LOGD("ngtcp2.conn == nullptr, close channel directly");
            onConnClose();
            return;
        }
        // 如果链接处于主动关闭或被动关闭状态，不需要任何处理，等它的计时器跑完即可.
        // 需要注意的是 NGTCP2_ERR_HANDSHAKE_TIMEOUT 这种情况，此时是没有计时器的，
        // 因为计时器的触发时间在过去某个时间点
        if (ngtcp2_conn_in_closing_period(mConn) || ngtcp2_conn_in_draining_period(mConn)) {
            if (uv_is_active(reinterpret_cast<uv_handle_t*>(&mTimer))) {
                LOGD("ngtcp2 is closing/draining, waiting for timer");
            } else {
                LOGD("ngtcp2 is closing/draining, but no timer, close it directly");
                onConnClose();
            }
            return;
        }
        // 链接正常，发送 CLOSE 帧
        LOGD("ngtcp2 conn ok, send CLOSE frame to close gracefully");
        {
            WriteHelper helper(mConn, uv_hrtime());
            writeCloseAndFlush(helper);
            helper.write(&mUdp, 0);
        }
        updateTimer();

        // 容错：如果此时链接仍然没进入关闭状态，强制杀掉
        if (!ngtcp2_conn_in_closing_period(mConn) && !ngtcp2_conn_in_draining_period(mConn)) {
            LOGE("failed to enter close state, force close !");
            onConnClose();
        }
    }

    void onConnClose() {
        LOGD("onConnClose !");

        // TODO 移除正在等待写入的数据，并通知 promise
        ngtcp2_conn_del(mConn);
        mConn = nullptr;

        // 关闭整条流水线
        if (mPipeline.isActive()) {
            mPipeline.fireChannelInactive();
        }
        mPipeline.removeAllHandlers();
        setResult(true, mCloseFuture);

        // 关闭定时器和 udp socket
        mUvCloser.reset(this, +[](Ngtcp2SocketChannel *self) {
            self->mSelf.reset();
        });
        mUvCloser.close(reinterpret_cast<uv_handle_t*>(&mTimer));
        mUvCloser.close(reinterpret_cast<uv_handle_t*>(&mUdp));
    }

public:
    Ngtcp2SocketChannel() = default;
    NO_COPY(Ngtcp2SocketChannel)
};

}

#endif