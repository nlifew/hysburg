
#ifndef HYSBURG_NGTCP2_SOCKET_CHANNEL_HPP
#define HYSBURG_NGTCP2_SOCKET_CHANNEL_HPP

#include <cassert>
#include <openssl/rand.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include "Util.hpp"
#include "channel/EventLoop.hpp"
#include "channel/Channel.hpp"
#include "udp/UdpSocket.h"

namespace hysburg {

enum Ngtcp2ChannelOption {
};

enum class StreamMsgType {
    OPEN, READ, WRITE, FLUSH, CLOSE
};

struct StreamMsg {
    StreamMsgType type = StreamMsgType::OPEN;
    int64_t streamId = INT64_MAX;
    ByteBuf byteBuf;
};

namespace internal {

/**
 * 侵入式链表
 * @tparam T
 */
template<typename T>
class LinkedList {
    T *mHead = nullptr;
    T *mTail = nullptr;

    T *doRemove(T *value) {
        auto prev = value->mPrev;
        auto next = value->mNext;

        if (prev != nullptr) { prev->mNext = next; }
        if (next != nullptr) { next->mPrev = prev; }

        if (value == mHead) { mHead = next; }
        if (value == mTail) { mTail = prev; }

        value->mPrev = value->mNext = nullptr;
        return value;
    }

    T *doInsert(T *prev, T *value) {
        assert(value->mPrev == nullptr && value->mNext == nullptr);

        auto *next = prev ? prev->mNext: mHead;
        value->mPrev = prev;
        value->mNext = next;

        if (prev == nullptr) {
            mHead = value;
        } else {
            prev->mNext = value;
        }
        if (next == nullptr) {
            mTail = value;
        } else {
            next->mPrev = value;
        }
        return value;
    }

public:
    explicit LinkedList() = default;
    NO_COPY(LinkedList)

    T* removeFirst() { return empty() ? nullptr : doRemove(mHead); }
    T* addFirst(T *value) { return doInsert(nullptr, value); }
    T *addLast(T *value) { return doInsert(mTail, value); }

    T *remove(T *value) { return doRemove(value); }

    bool contains(T *value) {
        for (auto it = mHead; it; it = it->mNext) {
            if (it == value) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]]
    T* first() { return mHead; }

    [[nodiscard]]
    const T* first() const { return mHead; }

    [[nodiscard]]
    bool empty() const { return mHead == nullptr; }
};

// 编译期雷达：在变长参数列表 Args... 中，找到第一个 void* 的索引位置
template <typename... Args>
constexpr size_t find_user_data_idx() {
    if constexpr (sizeof...(Args) == 0) {
        return static_cast<size_t>(-1);
    } else {
        // 展开所有参数的类型比较结果，比如 {false, false, false, true, false}
        bool match[] = { std::is_same_v<Args, void*>... };
        for (size_t i = 0; i < sizeof...(Args); ++i) {
            if (match[i]) return i; // 返回第一个匹配到的 void* 索引
        }
        return static_cast<size_t>(-1);
    }
}

template <auto MemFn>
struct Ngtcp2Thunk {};

// 偏特化：提取成员函数的返回值(R)、类类型(Class)和变长参数(Args...)
template <typename Class, typename R, typename... Args, R (Class::*MemFn)(Args...)>
struct Ngtcp2Thunk<MemFn> {
    static R invoke(Args... args) {
        // 1. 编译期算出 user_data 在参数包中的精准下标！零运行时开销。
        constexpr size_t idx = find_user_data_idx<Args...>();
        static_assert(
                idx != static_cast<size_t>(-1),
                "The callback signature must contain a 'void*' argument for user_data."
        );

        // 2. 将所有参数打包成 tuple
        auto t = std::forward_as_tuple(args...);
        // 3. 取出实例指针
        auto* self = static_cast<Class*>(std::get<idx>(t));
        // 4. 发起成员函数调用
        return (self->*MemFn)(args...);
    }
};


class ReferenceCounter {
    int mCount = 0;
    std::function<void()> mPending;
public:
    ReferenceCounter() = default;
    NO_COPY(ReferenceCounter)
    ~ReferenceCounter() { CHECK(mCount == 0, "invalid state") }

    template<typename T>
    void doWhenZero(T func) {
        if (mCount == 0) {
            func();
        } else {
            mPending = std::move(func);
        }
    }

    void operator()(int diff) {
        if ((mCount += diff) != 0) {
            return;
        }
        if (auto func = std::move(mPending); func != nullptr) {
            func();
        }
    }
};

}

struct Ngtcp2SocketChannel: public Channel {

    /**
     * ngtcp2 相关
     */
    ngtcp2_conn *mConn = nullptr;
    ngtcp2_ccerr mCCError {};
    ngtcp2_settings mSettings {};
    ngtcp2_callbacks mCallbacks {};
    ngtcp2_transport_params mParams {};
    ngtcp2_cid mScid {}, mDicd {};
    ngtcp2_path mPath {};
    ngtcp2_crypto_conn_ref mConnRef {};

    /**
     * UDP 相关
     */
    UdpSocket mSocket;
    uv_timer_t mTimer {};
    uv_timer_t mScheduleWriteTimer {};
    internal::ReferenceCounter mUvCloser;

    struct {
        bool isBlocked = false;
        // TODO 增加 ecn 支持
        size_t geoSize = 0;
        /**
         * 当发送缓冲区已满时, data 是指向 blocked 的一块内存，用来表示需要发送的 udp 数据。
         * 随着发送的继续，data 不断减小，但 blocked 保持不变。data 为空时，blocked 内存才会彻底释放
         */
        std::span<uint8_t> data;
        std::vector<uint8_t> blocked;
    } mTx;

    /**
     * SSL 相关
     */
    std::vector<uint8_t> mAlpn;
    SSL_CTX *mSSLCtx = nullptr;
    std::unique_ptr<SSL, void(*)(SSL*)> mSSL { nullptr, SSL_free };

    /**
     * stream 管理
     */
    struct WriteOnce {
        ByteBuf byteBuf;
        PromisePtr<void> promise;
        size_t originalReadIndex = 0; // byteBuf 备份下来的读指针
    };

    struct Stream {
        static constexpr int FLAG_BLOCKED = 1;
        static constexpr int FLAG_FIN = 2;

        int64_t id = UINT64_MAX;
        Stream *mNext = nullptr, *mPrev = nullptr;
        int flags = 0;


        // TODO mQueue 放在 Stream 维度可能会产生公平问题。即数据包的发送顺序完全依赖于 Stream 的遍历顺序
        // [0, mWritingSize) 表示已写入未 ack 的部分;
        // [mWriting, mQueue.size) 表示还未写入的部分
        std::deque<WriteOnce> mQueue;
        size_t mWritingSize = 0;

        [[nodiscard]] size_t pendingSize() const { return mQueue.size() - mWritingSize; }
        [[nodiscard]] size_t writingSize() const { return mWritingSize; }

        WriteOnce &getWriting(size_t index) { return mQueue[index]; }
        WriteOnce &getPending(size_t index) { return mQueue[mWritingSize + index]; }

        void movePendingToWriting() { mWritingSize += 1; }
        void popWriting() { mQueue.pop_front(); mWritingSize -= 1; }
        WriteOnce &pushPending() { return mQueue.emplace_back(); }
    };

    std::map<int64_t, Stream> mStreamMap;

    /**
     * 有数据等待发送的 Stream 集合
     */
    internal::LinkedList<Stream> mSendQueue;

    /**
     * 因为各种原因，虽然有数据等待发送，但被跳过的 Stream 集合
     * 比如触发 stream 流控
     */
    internal::LinkedList<Stream> mBlockedQueue;

    void initSettings() {
        ngtcp2_settings_default(&mSettings);
        mSettings.cc_algo = ngtcp2_cc_algo::NGTCP2_CC_ALGO_BBR;
        mSettings.initial_ts = uv_hrtime();
        mSettings.handshake_timeout = 10 * NGTCP2_SECONDS;
    }

    void initParams() {
        ngtcp2_transport_params_default(&mParams);
        mParams.initial_max_data = 1 * 1024 * 1024;
        mParams.initial_max_stream_data_bidi_local = 1 * 1024 * 1024;
        mParams.initial_max_stream_data_bidi_remote = 1 * 1024 * 1024;
        mParams.initial_max_streams_bidi = UINT32_MAX;
        mParams.grease_quic_bit = 1;
        mParams.max_idle_timeout = 30 * NGTCP2_SECONDS;
//        mParams.max_udp_payload_size = NGTCP2_MAX_UDP_PAYLOAD_SIZE;
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
        X(get_path_challenge_data2);
        X(version_negotiation);
#undef X
#undef ADD3
        mCallbacks.rand = [](uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx) {
            RAND_bytes(dest, destlen);
        };
        mCallbacks.get_new_connection_id2 = [](
                ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
                size_t cidlen, void *user_data
        ) -> int {
            cid->datalen = cidlen;
            RAND_bytes(cid->data, cidlen);
            RAND_bytes(token->data, NGTCP2_STATELESS_RESET_TOKENLEN);
            return 0;
        };

#define X(NAME) mCallbacks.NAME = (internal::Ngtcp2Thunk<&Ngtcp2SocketChannel::on_##NAME>::invoke)
        X(handshake_confirmed);
        X(recv_stream_data);
        X(stream_open);
        X(extend_max_stream_data);
        X(acked_stream_data_offset);
        X(stream_close);
        // TODO 增加对 stream_reset 的支持
#undef X
    }

    int on_handshake_confirmed(ngtcp2_conn *conn, void *user_data) {
        LOGD("handshake confirmed");
        mPipeline.fireChannelActive();
        setResult(true, mConnectPromise);
        return 0;
    }

    int on_stream_open(ngtcp2_conn *conn, int64_t stream_id, void *user_data) {
        Stream stream {};
        stream.id = stream_id;
        mStreamMap.insert({ stream_id, std::move(stream) });

        AnyPtr any;
        auto msg = makeAnyIn<StreamMsg>(any);
        msg->streamId = stream_id;
        msg->type = StreamMsgType::OPEN;
        mPipeline.fireChannelRead(std::move(any));
        return 0;
    }

    int on_acked_stream_data_offset(
            ngtcp2_conn *conn, int64_t stream_id,
            uint64_t offset, uint64_t datalen,
            void *user_data, void *stream_user_data
    ) {
        auto stream = findStreamById(stream_id);
        if (stream == nullptr) {
            return 0;
        }
        while (stream->writingSize() > 0) {
            auto &byteBuf = stream->getWriting(0).byteBuf;
            auto consumed = std::min(byteBuf.readableBytes(), (size_t) datalen);
            byteBuf.offsetReader(consumed);
            datalen -= consumed;
            if (byteBuf.readableBytes() > 0) {
                break;
            }
            stream->popWriting();
        }
        CHECK(datalen == 0, "impossible here")
        return 0;
    }

    int on_recv_stream_data(
            ngtcp2_conn *conn, uint32_t flags,
            int64_t stream_id, uint64_t offset,
            const uint8_t *data, size_t datalen,
            void *user_data, void *stream_user_data
    ) {
        AnyPtr any;
        auto msg = makeAnyIn<StreamMsg>(any);
        msg->streamId = stream_id;
        msg->type = StreamMsgType::READ;
        msg->byteBuf.writeBytes(data, datalen);
        mPipeline.fireChannelRead(std::move(any));

        ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
        ngtcp2_conn_extend_max_offset(conn, datalen);
        return 0;
    }

    /**
     * 监听 extend_max_stream_data 回调，让被阻塞的流重新回到 sendQueue
     */
    int on_extend_max_stream_data(
            ngtcp2_conn *conn,
            int64_t stream_id,
            uint64_t max_data, void *user_data,
            void *stream_user_data
    ) {
        auto stream = findStreamById(stream_id);
        if (stream == nullptr) {
            return 0;
        }
        if (stream->flags & Stream::FLAG_BLOCKED) {
            unblockStream(stream);
            scheduleWrite();
        }
        return 0;
    }

    int on_stream_close(
            ngtcp2_conn *conn, uint32_t flags,
            int64_t stream_id, uint64_t app_error_code,
            void *user_data, void *stream_user_data
    ) {
        if (auto stream = findStreamById(stream_id); stream != nullptr) {
            if (stream->flags & Stream::FLAG_BLOCKED) {
                mBlockedQueue.remove(stream);
            } else {
                mSendQueue.remove(stream);
            }
            // TODO 残留的 promise 怎么通知 ?
        }
        mStreamMap.erase(stream_id);

        AnyPtr any;
        auto msg = makeAnyIn<StreamMsg>(any);
        msg->streamId = stream_id;
        msg->type = StreamMsgType::CLOSE;
        mPipeline.fireChannelRead(std::move(any));
        return 0;
    }


    void doRegister() override {
        mTimer.data = this;
        uv_timer_init(mExecutor->handle(), &mTimer);
        
        mScheduleWriteTimer.data = this;
        uv_timer_init(mExecutor->handle(), &mScheduleWriteTimer);

        // 先不着急初始化 socket fd，延迟初始化至 bind/connect

        initCallback();
        initSettings();
        initParams();

        mPipeline.addAllHandlers(mExecutor);
        setResult(true, mRegisterPromise);
    }

    void doBind() override {
        auto ret = mSocket.bind(mLocalAddress.storage);
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
        // 不过由于存在微小的时间差，udp socket 仍然有可能收到来自其他地址的 udp 包。
        if (auto ret = mSocket.connect(mRemoteAddress.storage); ret < 0) {
            return ret;
        }
        if (auto ret = mSocket.getLocalAddress(&mLocalAddress.storage); ret < 0) {
            return ret;
        }
        // 非阻塞 & mtu 路径发现 & ecn
        int ret = 0;
        ret |= mSocket.setNonBlocking(true);
        ret |= mSocket.setMtuDiscoverEnabled(true);
        ret |= mSocket.setPkiInfoEnabled(true);
//        ret |= mSocket.setEcnEnabled(true);

        // 初始化 udp 收消息逻辑
        ret |= mSocket.start(mExecutor->handle(), UdpSocket::FLAG_READABLE, [this](int flags) {
            if ((flags & UdpSocket::FLAG_READABLE)) {
                on_read();
            }
            if ((flags & UdpSocket::FLAG_WRITABLE)) {
                on_write();
            }
        });
        return ret;
    }

    int ngtcp2Connect() {
        mScid.datalen = mDicd.datalen = NGTCP2_MAX_CIDLEN;
        RAND_bytes(mScid.data, NGTCP2_MAX_CIDLEN);
        RAND_bytes(mDicd.data, NGTCP2_MAX_CIDLEN);

        mPath = {
                .local = { .addr = &mLocalAddress.addr, .addrlen = Net::getSockLen(mLocalAddress.addr.sa_family) },
                .remote = { .addr = &mRemoteAddress.addr, .addrlen = Net::getSockLen(mRemoteAddress.addr.sa_family) },
                .user_data = nullptr,
        };
        return ngtcp2_conn_client_new(
                &mConn, &mDicd, &mScid,
                &mPath,
                NGTCP2_PROTO_VER_V1,
                &mCallbacks, &mSettings, &mParams,
                ngtcp2_mem_default(), this
        );
    }

    void doConnect() override {
        // 想了一下还是吧 ngtcp2_conn 的初始化放在最后面
        // 只要这个 conn 为 nullptr 就说明没有 connect 完成。
        if (sslConnect() != 0 || udpConnect() != 0 || ngtcp2Connect() != 0) {
            setResult(false, mConnectPromise);
            return;
        }
        ngtcp2_conn_set_tls_native_handle(mConn, mSSL.get());
        on_write();
    }

    void on_read() {
        // 准备 64kb 的缓冲区，分成 32 个包，每个包 2048 字节。
        // 注意这里的 2048 只是经验之谈。理论上讲确实有消息截断的可能，但是
        // 可能性到底有多大？我们真的需要保证绝对的正确性准备 64kb 的小包吗 ?
        // 答案是否定的，2048 应该足够在绝大多数场景下正常工作了。
        constexpr size_t PER_PACKET_SIZE = 2048;
        constexpr size_t PACKETS_NUM = 32;

        std::array<uint8_t, PACKETS_NUM * PER_PACKET_SIZE> dataArray;   // NOLINT(*-pro-type-member-init)
        std::array<UdpSocket::Packet, PACKETS_NUM> packetArray;         // NOLINT(*-pro-type-member-init)
        std::array<iovec, PACKETS_NUM> iovecArray;                      // NOLINT(*-pro-type-member-init)
        std::array<sockaddr_storage, PACKETS_NUM> destArray;            // NOLINT(*-pro-type-member-init)
        std::array<sockaddr_storage, PACKETS_NUM> srcArray;             // NOLINT(*-pro-type-member-init)

        for (size_t i = 0; i < PACKETS_NUM; ++i) {
            auto &vec = iovecArray[i] = {
                    .iov_base = dataArray.data() + i * PER_PACKET_SIZE,
                    .iov_len = PER_PACKET_SIZE,
            };
            packetArray[i] = {
                    .src = &srcArray[i],
                    .dest = &destArray[i],
                    .vec = { &vec, 1 },
                    .dataLen = 0,
                    .flag = 0,
            };
        }

        // 收包。注意：为了防止事件饥饿，不要死循环一直收包
        // 这对 bbr 等对时延敏感的 cc 算法的影响更大
        auto num = mSocket.recvFrom(packetArray);
        if (num <= 0) {
            // 当udp不可达时，内核会收到ICMP消息，libuv 会将其视为可读事件向上层回调
            // 这里直接返回就好了
            LOGD("error, mSocket.recvFrom()='%zd'", num);
            return;
        }

        for (int i = 0; i < num; ++i) {
            std::span<uint8_t> data = {
                    static_cast<uint8_t*>(iovecArray[i].iov_base),
                    static_cast<size_t>(packetArray[i].dataLen),
            };
            if (!isRecvUdpDataOk(data)) {
                continue;
            }
            if (feed_data(data, srcArray[i], destArray[i]) < 0) {
                return;
            }
        }
        on_write();
    }

    bool isRecvUdpDataOk(std::span<uint8_t> data) {
        // 必须要做一个检查，udp 初始化早于 conn，销毁晚于 conn
        if (mConn == nullptr) {
            return false;
        }
        // 小于 21 字节的必不可能是 quic 包
        if (data.size() < 21) {
            return false;
        }
//        // 注意 addr 并不一定就等于 mRemoteAddress。因为在 udp connect 之前，
//        // 内核并不会过滤掉其他地址的 udp 包。udp socket 在初始化到 connect 之间肯定有时间间隔的
//        // 考虑到服务器地址不会改变，这里简单做一下过滤
//        if (!Net::equals(&mRemoteAddress.storage, &addr)) {
//            return false;
//        }
        return true;
    }

    int feed_data(std::span<uint8_t> data, sockaddr_storage &src, sockaddr_storage &dest) {
        ngtcp2_path path = {
                .local = {
                        .addr = reinterpret_cast<sockaddr*>(&dest),
                        .addrlen = Net::getSockLen(dest.ss_family),
                },
                .remote = {
                        .addr = reinterpret_cast<sockaddr*>(&src),
                        .addrlen = Net::getSockLen(src.ss_family),
                },
                .user_data = nullptr,
        };

        // TODO 增加 ecn 支持
        auto ret = ngtcp2_conn_read_pkt(
                mConn, &path, nullptr, data.data(), data.size(), uv_hrtime()
        );
        if (ret != 0) {
            LOGD("ngtcp2_conn_read_pkt()='%d'(%s)", ret, ngtcp2_strerror(ret));
        }
        switch (ret) {
            case NGTCP2_NO_ERROR:
            // 链接即将消亡或者已经发送过 close 帧，不需要任何处理
            case NGTCP2_ERR_DRAINING:
            case NGTCP2_ERR_CLOSING:
                return 0;
            case NGTCP2_ERR_CRYPTO:
                ngtcp2_ccerr_set_tls_alert(
                        &mCCError, ngtcp2_conn_get_tls_alert(mConn), nullptr, 0
                );
                break;
            default:
                ngtcp2_ccerr_set_liberr(&mCCError, ret, nullptr, 0);
                break;
        }
        doClose();
        return -1;
    }

    Stream *findStreamById(int64_t id) {
        auto it = mStreamMap.find(id);
        return it == mStreamMap.end() ? nullptr : &it->second;
    }

    /**
     * 和 on_write 不同：设置一个定时器，在定时器中执行 on_write。
     * 防止重入 ngtcp2
     */
    void scheduleWrite() {
        if (uv_is_active(reinterpret_cast<uv_handle_t*>(&mScheduleWriteTimer))) {
            return;
        }
        uv_timer_start(&mScheduleWriteTimer, [](uv_timer_t *timer) {
            uv_timer_stop(timer);
            static_cast<Ngtcp2SocketChannel*>(timer->data)->on_write();
        }, 0, 0);
    }

    void on_write() {
        if (mTx.isBlocked) {
            send_blocked_packet();
            if (mTx.isBlocked) {
                return;
            }
        }
        if (ngtcp2_conn_in_closing_period(mConn)) {
            write_close_frame();
        } else if (ngtcp2_conn_in_draining_period(mConn)) {
            LOGD("is in draining, nothing to do");
        } else {
            write_streams();
        }
        update_timer();
    }

    void send_blocked_packet() {
        assert(mTx.isBlocked);

        auto rest = send_packet(mTx.data, mTx.geoSize);
        if (!rest.empty()) {
            // 走进这个分支说明这次只发送了一部分
            mTx.data = rest;
            // 发送失败，订阅 socket 可写事件
            // 这一步是必要的，因为 on_write() 并不一定就是从 socket 的可写事件里调用过来
            mSocket.start(UdpSocket::FLAG_READABLE | UdpSocket::FLAG_WRITABLE);
            return;
        }
        // 发送成功，取消 block 状态
        mTx.isBlocked = false;
        mTx.data = {};
        mTx.blocked.clear();
        mTx.blocked.shrink_to_fit();
        mSocket.start(UdpSocket::FLAG_READABLE);
    }

    ssize_t write_close_frame() {
        // 准备生成 CLOSE 帧
        std::array<uint8_t, NGTCP2_MAX_UDP_PAYLOAD_SIZE> dataArray; // NOLINT(*-pro-type-member-init)

        auto ret = ngtcp2_conn_write_connection_close(
                mConn, nullptr, nullptr,
                dataArray.data(), dataArray.size(), &mCCError,
                uv_hrtime()
        );
        if (ret < 0) {
            LOGD("send CLOSE frame failed (%s)", ngtcp2_strerror(ret));
        }
        if (ret > 0) {
            send_packet_or_blocked({ dataArray.data(), static_cast<size_t>(ret) }, ret);
            LOGD("send CLOSE frame ok (%td bytes)", ret);
        }
        if (ret == 0) {
            LOGD("no new CLOSE frame generated, ignore");
        }
        return ret;
    }

    ngtcp2_ssize write_streams() {
        auto ts = uv_hrtime();

        size_t gsoSize = 0;
        std::array<uint8_t, NGTCP2_MAX_TX_UDP_PAYLOAD_SIZE> dataArray;  // NOLINT(*-pro-type-member-init)

        std::span<uint8_t> data = dataArray;
        auto impl = [](
                ngtcp2_conn *conn, ngtcp2_path *path,
                ngtcp2_pkt_info *pi, uint8_t *dest,
                size_t destlen, ngtcp2_tstamp ts,
                void *user_data
        ) -> ngtcp2_ssize {
            auto self = static_cast<Ngtcp2SocketChannel*>(user_data);
            return self->write_pkt(path, pi, dest, destlen, ts);
        };
        // ngtcp2_conn_write_aggregate_pkt() 内部会取 ngtcp2_conn_get_send_quantum() 和 bufSize 较小的那个
        auto bytes = ngtcp2_conn_write_aggregate_pkt(
                mConn, nullptr, nullptr,
                data.data(), data.size(), &gsoSize, impl, ts
        );
        if (bytes < 0) {
            LOGD("ngtcp2_conn_write_aggregate_pkt()=(%s)", ngtcp2_strerror(bytes));
            doClose();
            return -1;
        }
        if (bytes > 0) {
            send_packet_or_blocked(data.first(bytes), gsoSize);
        }
        return bytes;
    }

    // ---- write_pkt 及其辅助函数 ----------------------------------------

    struct WritePktParam {
        Stream               *stream = nullptr;
        std::span<ngtcp2_vec> vec    = {};
        uint32_t              flags  = 0;
    };

    /**
     * 从 mSendQueue 取下一个可写的 stream，填好 iov 和 flags。
     * 队列空或连接级流控耗尽时返回 {nullptr, {}, 0}，表示只写控制帧。
     */
    WritePktParam pickStream(std::span<ngtcp2_vec> vecArray) {
        if (mSendQueue.empty() || ngtcp2_conn_get_max_data_left(mConn) <= 0) {
            return {};
        }

        auto stream = mSendQueue.removeFirst();

        std::span<ngtcp2_vec> vec = {
                vecArray.data(),
                std::min(vecArray.size(), stream->pendingSize()),
        };
        for (size_t i = 0; i < vec.size(); i++) {
            auto &byteBuf = stream->getPending(i).byteBuf;
            vec[i] = {
                    .base = reinterpret_cast<uint8_t*>(byteBuf.readData()),
                    .len = byteBuf.readableBytes(),
            };
        }

        uint32_t flag = NGTCP2_WRITE_STREAM_FLAG_MORE;
        if ((stream->flags & Stream::FLAG_FIN) && vec.size() == stream->pendingSize()) {
            flag |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
        return { stream, vec, flag };
    }

    /** stream 还有剩余数据时重新放回队头，等待下一轮写入。 */
    void requeueStream(Stream *stream) {
        if (stream && stream->pendingSize() > 0) {
            mSendQueue.addFirst(stream);
        }
    }

    /** 标记 stream 为 blocked 并移入 mBlockedQueue。 */
    void blockStream(Stream *stream) {
        assert((stream->flags & Stream::FLAG_BLOCKED) == 0);
        stream->flags |= Stream::FLAG_BLOCKED;
        mSendQueue.remove(stream);
        mBlockedQueue.addLast(stream);
    }

    /** 取消标记 stream 为 blocked，并从 mBlockedQueue 移除 */
    void unblockStream(Stream *stream) {
        // 理论上讲，这个 stream 一定在 mBlockedQueue 里
        assert(stream->flags & Stream::FLAG_BLOCKED);
        stream->flags &= ~Stream::FLAG_BLOCKED;
        mBlockedQueue.remove(stream);
        mSendQueue.addLast(stream);
    }

    /**
     * 作为 ngtcp2_conn_write_aggregate_pkt 的回调，尽量把 dest 缓冲区填满
     */
    ngtcp2_ssize write_pkt(ngtcp2_path *path, ngtcp2_pkt_info *pi,
            uint8_t *dest, size_t destlen, ngtcp2_tstamp ts
    ) {
        std::array<ngtcp2_vec, 64> vecBuf; // NOLINT(*-pro-type-member-init)

        while (true) {
            auto [stream, vec, flags] = pickStream(vecBuf);

            ngtcp2_ssize datalen = 0;
            auto bytes = ngtcp2_conn_writev_stream(
                    mConn, path, pi, dest, destlen, &datalen, flags,
                    stream ? stream->id : -1,
                    vec.data(), vec.size(), ts
            );
            movePendingToWriting(stream, datalen);
            requeueStream(stream);

            switch (bytes) {
                case NGTCP2_ERR_WRITE_MORE:
                    continue;

                case NGTCP2_ERR_STREAM_DATA_BLOCKED:
                case NGTCP2_ERR_STREAM_SHUT_WR:
                case NGTCP2_ERR_STREAM_NOT_FOUND:
                    // 该 stream 被流控阻塞，换下一个
                    blockStream(stream);
                    continue;

                case NGTCP2_ERR_CLOSING:
                case NGTCP2_ERR_DRAINING:
                    return 0;
                default: break;
            }
            if (bytes < 0) {
                LOGD("ngtcp2_conn_writev_stream() = %td(%s)", bytes, ngtcp2_strerror(bytes));
                ngtcp2_ccerr_set_liberr(&mCCError, bytes, nullptr, 0);
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }
            return bytes;
        }
    }

    void movePendingToWriting(Stream *stream, ssize_t datalen) {
        if (datalen <= 0 || stream == nullptr) {
            return;
        }
        while (stream->pendingSize() > 0) {
            auto &once = stream->getPending(0);
            auto &byteBuf = once.byteBuf;
            auto consumed = std::min(byteBuf.readableBytes(), (size_t) datalen);
            datalen -= consumed;
            byteBuf.offsetReader(consumed);

            if (byteBuf.readableBytes() > 0) {
                break;
            }
            // 全部消耗完：还原读指针供 ack 追踪，回调 promise，推进边界
            byteBuf.readIndex(once.originalReadIndex);
            stream->movePendingToWriting();
            setResult(true, once.promise);
        }
        CHECK(datalen == 0, "impossible here")
    }


    /**
     * 把数据包按照 geosize 拆分成若干个小包并尝试发送
     */
    std::span<uint8_t> send_packet(std::span<uint8_t> data, size_t geoSize) {
        assert(geoSize > 0);

        std::array<iovec, 64> iovecArray;               // NOLINT(*-pro-type-member-init)
        std::array<UdpSocket::Packet, 64> packetArray;  // NOLINT(*-pro-type-member-init)

        for (size_t i = 0; i < iovecArray.size(); ++i) {
            packetArray[i] = {
                    .src = nullptr,
                    .dest = nullptr,
                    .vec = { &iovecArray[i], 1 },
                    .dataLen = 0,
                    .flag = 0,
            };
        }

        while (true) {
            auto n = static_cast<size_t>(std::min(std::ceil(1.0 * data.size() / geoSize), 64.0));
            if (n == 0) {
                break;
            }
            for (size_t i = 0; i < n; ++i) {
                iovecArray[i] = {
                        .iov_base = data.data() + i * geoSize,
                        .iov_len = std::min(geoSize, data.size() - i * geoSize),
                };
            }

            ssize_t bytes = 0;
            auto num = mSocket.sendTo({ packetArray.data(), n });
            for (ssize_t i = 0; i < num; i ++) {
                bytes += packetArray[i].dataLen;
            }
            if (bytes <= 0) break;
            data = data.subspan(bytes);
        }
        return data;
    }

    void send_packet_or_blocked(std::span<uint8_t> data, size_t geoSize) {
        auto rest = send_packet(data, geoSize);
        if (!rest.empty()) {
            // 进入这个分支说明发送失败了，udp socket 写缓冲区已满
            assert(!mTx.isBlocked && geoSize > 0);

            // 把来自栈上缓冲区的数据拷贝到 mTx.blocked 缓冲区，以防止 rest 指针失效
            mTx.blocked.assign(rest.begin(), rest.end());
            mTx.data = mTx.blocked;
            mTx.isBlocked = true;
            mTx.geoSize = geoSize;
            mSocket.start(UdpSocket::FLAG_READABLE | UdpSocket::FLAG_WRITABLE);
        }
    }

    void update_timer() {
        // CLOSING/DRAINING 期间，ngtcp2_conn_get_expiry() 的值仅用于触发 CONNECTION_CLOSE 重传，
        // 而重传已由 on_read() -> on_write() -> write_close_frame() 覆盖，无需依赖定时器。
        // 按照 RFC 9000 §10.2 的建议，等待 3×PTO 后直接调用 onConnClose() 清理连接状态。
        if (ngtcp2_conn_in_closing_period(mConn) || ngtcp2_conn_in_draining_period(mConn)) {
            auto delay = std::max(3 * ngtcp2_conn_get_pto(mConn) / NGTCP2_MILLISECONDS, (uint64_t) 500);
            LOGD("next tick: %llu ms. (conn is in closing/draining)", delay);

            uv_timer_start(&mTimer, [](uv_timer_t *handle) {
                static_cast<Ngtcp2SocketChannel*>(handle->data)->onConnClose();
            }, delay, 0);
            return;
        }

        const auto expiry = ngtcp2_conn_get_expiry(mConn);
        if (expiry == UINT64_MAX) {
            LOGD("ngtcp2_conn_get_expiry() == UINT64_MAX, cancel timer");
            uv_timer_stop(&mTimer);
            return;
        }

        uint64_t diff = 0;
        auto now = uv_hrtime();
        if (now > expiry) {
            LOGD("next tick: expired '%lld' ms, reset to 0", (now - expiry) / NGTCP2_MILLISECONDS);
        } else {
            diff = std::max((expiry - now) / NGTCP2_MILLISECONDS, (uint64_t) 1); // [1]
            LOGD("next tick: '%lld' ms", diff);
        }
        // [1]. 向上取整，防止多次自旋。libuv 可能会在定时器到达之前就唤醒 timeout，
        // 如果不取整，diff 是 0，会在下次事件循环中立即调用 timeout，一直自旋直到时间真的到达
        uv_timer_start(&mTimer, [](uv_timer_t *handle) {
            static_cast<Ngtcp2SocketChannel*>(handle->data)->onTimeout();
        }, diff, 0);
    }

    void onTimeout() {
        LOGD("timeout !");
        auto ts = uv_hrtime();
        auto ret = ngtcp2_conn_handle_expiry(mConn, ts);
        if (ret == 0) {
            // 一切正常，调用 on_write() 发包并重置下次超时时间
            on_write();
            return;
        }
        LOGD("failed! ngtcp2_conn_handle_expiry() = %d(%s)", ret, ngtcp2_strerror(ret));
        if (ret == NGTCP2_ERR_IDLE_CLOSE || ret == NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
            // 这个链接可以静默丢弃了
            onConnClose();
            return;
        }
        // 调用 ngtcp2_conn_write_connection_close() 发送 close 包
        ngtcp2_ccerr_set_liberr(&mCCError, ret, nullptr, 0);
        doClose();
    }

    void doOption(int key, void *value) override {

    }

    void doListen(int backlog) override {
        setResult(false, mListenPromise);
    }

    void doWrite(AnyPtr msg, PromisePtr<void> promise) override {
        if (UNLIKELY(!msg->is<StreamMsg>())) {
            LOGE("unknown message type '%s', expected '%s'", msg->type.name(), typeid(StreamMsg).name());
            setResult(false, promise);
            return;
        }
        auto *streamMsg = msg->as<StreamMsg>();
        switch (streamMsg->type) {
            case StreamMsgType::OPEN:
                doOpenStream(promise);
                break;
            case StreamMsgType::READ:
                setResult(false, promise);
                break;
            case StreamMsgType::WRITE:
                doWriteStream(streamMsg->streamId, streamMsg->byteBuf, promise);
                break;
            case StreamMsgType::FLUSH:
                doFlushStream(promise);
                break;
            case StreamMsgType::CLOSE:
                doCloseStream(streamMsg->streamId, promise);
                break;
        }
    }

    int64_t doOpenStream(PromisePtr<void> &promise) {
        int64_t streamId = -1;
        auto ret = ngtcp2_conn_open_bidi_stream(mConn, &streamId, this);
        if (ret != 0) {
            setResult(false, promise);
            return INT64_MAX;
        }
        on_stream_open(mConn, streamId, this);
        setResult(true, promise);
        return streamId;
    }

    void doWriteStream(int64_t streamId, ByteBuf &msg, PromisePtr<void> &promise) {
        auto stream = findStreamById(streamId);
        if (stream == nullptr) {
            setResult(false, promise);
            return;
        }
        if (msg.readableBytes() <= 0) {
            setResult(true, promise);
            return;
        }
        auto &once = stream->pushPending();
        once.promise = promise;
        once.originalReadIndex = msg.readIndex();
        once.byteBuf = std::move(msg);

        if ((stream->flags & Stream::FLAG_BLOCKED) == 0 && !mSendQueue.contains(stream)) {
            mSendQueue.addLast(stream);
        }
    }

    void doFlushStream(PromisePtr<void> &promise) {
        scheduleWrite();
        setResult(true, promise);
    }

    void doCloseStream(int64_t streamId, PromisePtr<void> &promise) {
        auto stream = findStreamById(streamId);
        if (stream == nullptr) {
            setResult(false, promise);
            return;
        }
        stream->flags |= Stream::FLAG_FIN;
        if ((stream->flags & Stream::FLAG_BLOCKED) == 0 && !mSendQueue.contains(stream)) {
            mSendQueue.addLast(stream);
        }
        scheduleWrite();
        setResult(true, promise);
    }

    void doFlush() override {
        /* no-op */
    }

    void doClose() override {
        // 这个应该比较好理解，从来没发出过 connect 请求，此时直接关闭即可
        if (mConn == nullptr) {
            LOGD("ngtcp2.conn == nullptr, close channel directly");
            return;
        }
        // 如果正在关闭中，理论上不需要再次执行。也是为了防止把 CLOSE 帧从 mTX 里错误删除
        if (ngtcp2_conn_in_closing_period(mConn) || ngtcp2_conn_in_draining_period(mConn)) {
            return;
        }
        // 移除正在等待的未发送数据
        if (mTx.isBlocked) {
            mTx.isBlocked = false;
            mSocket.start(UdpSocket::FLAG_READABLE);
        }
        write_close_frame();
        update_timer();
    }

    void onConnClose() {
        LOGD("onConnClose !");

        // TODO 移除正在等待写入的数据，并通知 promise
        if (mConn) {
            ngtcp2_conn_del(mConn);
            mConn = nullptr;
        }
        mSocket.close();

        // 关闭定时器
        std::array<uv_timer_t*, 2> handles = { &mTimer, &mScheduleWriteTimer };
        mUvCloser(handles.size());
        mUvCloser.doWhenZero([this]() { mSelf.reset(); });
        for (const auto it : handles) {
            uv_timer_stop(it);
            uv_close(reinterpret_cast<uv_handle_t*>(it), [](uv_handle_t *handle) {
                static_cast<Ngtcp2SocketChannel*>(handle->data)->mUvCloser(-1);
            });
        }

        // 关闭整条流水线
        if (mPipeline.isActive()) {
            mPipeline.fireChannelInactive();
        }
        mPipeline.removeAllHandlers();

        // 如果正在连接中，报告连接失败
        if (!mConnectPromise->retain().isDone()) {
            setResult(false, mConnectPromise);
        }
        setResult(true, mCloseFuture);
    }

public:
    Ngtcp2SocketChannel() = default;
    NO_COPY(Ngtcp2SocketChannel)

    int setAlpn(std::string_view alpn) {
        if (alpn.size() > UINT8_MAX) {
            return -1;
        }
        mAlpn.clear();
        mAlpn.push_back(static_cast<uint8_t>(alpn.size()));
        mAlpn.insert(mAlpn.end(), alpn.begin(), alpn.end());
        return 0;
    }
};

}

#endif