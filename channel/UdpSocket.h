
#ifndef HYSBURG_UDPSOCKET_H
#define HYSBURG_UDPSOCKET_H

#include <unistd.h>
#include <uv.h>
#include "Util.hpp"

namespace hysburg
{

class UdpSocket
{
public:
    using OnReadableListener = std::function<void()>;

    static constexpr int FLAG_BIND = 1;
    static constexpr int FLAG_POLL_START = 1 << 1;
    static constexpr int FLAG_TRUNC = 1 << 2;
    static constexpr int FLAG_PKI_ENABLED = 1 << 3;
    static constexpr int FLAG_ECN_ENABLED = 1 << 4;

    struct Packet
    {
        sockaddr_storage *src;
        sockaddr_storage *dest;
        iovec *vec;
        int vecLen;
        int ecn;
        int dataLen;
        int flag;
    };

private:
    int mFamily = AF_UNSPEC;
    uv_os_sock_t mFd {};
    std::unique_ptr<uv_poll_t> mPoll;
    OnReadableListener mReadableListener = nullptr;

    sockaddr_storage mBindAddress {};

    int32_t mFlag = 0;
    int mLocalPort = 0;
    int initSocket(int family);
    void closeSocket();

public:
    explicit UdpSocket() = default;
    ~UdpSocket() noexcept { close(); }

    NO_COPY(UdpSocket)

    int initFd(int family) {
        if (auto ret = initSocket(family); ret < 0) {
            LOGE("failed to init socket: '%d', errno='%d'", mFd, errno);
            return ret;
        }
        return 0;
    }

    int bind(const sockaddr_storage &local);
    int getLocalAddress(sockaddr_storage *out);

    int getLocalPort() {
        if (mLocalPort <= 0) {
            sockaddr_storage local {};
            getLocalAddress(&local);
            mLocalPort = Net::portOf(local);
        }
        return mLocalPort <= 0 ? -1 : mLocalPort;
    }

    [[nodiscard]]
    bool isBind() const noexcept { return (mFlag & FLAG_BIND) != 0; }

    int setSocketBuffSize(int bufSize);
//    int setGsoEnabled(bool enabled);
//    int setGroEnabled(bool enabled);
    int setEcnEnabled(bool enabled);
    int setNonBlocking(bool nonBlocking);
    int setReuseAddr(bool reuse);
    int setMtuDiscoverEnabled(bool enabled);
    int setPkiInfoEnabled(bool enabled);
    int setRxqOvflEnabled(bool enabled);

    ssize_t sendTo(Packet *packets, int len);
    ssize_t recvFrom(Packet *packets, int len);

    int poll(uv_loop_t *loop, OnReadableListener listener) {
        mReadableListener = std::move(listener);

        mPoll = std::make_unique<uv_poll_t>();
        if (auto ret = uv_poll_init_socket(loop, mPoll.get(), mFd); ret < 0) {
            LOGE("failed to init uv_poll_t: '%d'", ret);
            return ret;
        }
        mPoll->data = this;

        uv_poll_cb callback = [](uv_poll_t* handle, int status, int events) {
            LOGI("uv_poll_start callback: status='%d', events='%d'", status, events);
            if (status != 0 || (events & UV_READABLE) == 0) {
                return ;
            }
            auto self = static_cast<UdpSocket*>(handle->data);
            if (self->mReadableListener != nullptr) {
                self->mReadableListener();
            }
        };
        if (auto ret = uv_poll_start(mPoll.get(), UV_READABLE, callback); ret < 0) {
            return ret;
        }
        mFlag |= FLAG_POLL_START;
        return 0;
    }

    int stop() {
        if (auto ret = uv_poll_stop(mPoll.get()); ret < 0) {
            return ret;
        }
        mFlag &= ~FLAG_POLL_START;
        return 0;
    }

    void close() {
        if (mPoll != nullptr) {
            if ((mFlag & FLAG_POLL_START) != 0) {
                stop();
            }
            uv_close((uv_handle_t *) mPoll.release(), [](uv_handle_t* handle) {
                delete handle;
            });
        }
        closeSocket();
        bzero(&mBindAddress, sizeof(mBindAddress));
        mLocalPort = 0;
        mFlag = 0;
        mFd = -1;
        mFamily = 0;
    }
};
}

#endif // HYSBURG_UDPSOCKET_H