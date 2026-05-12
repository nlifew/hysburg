
#ifndef HYSBURG_UDPSOCKET_H
#define HYSBURG_UDPSOCKET_H

#include <functional>
#include <memory>
#include <span>

#include <uv.h>
#include "Util.hpp"

namespace hysburg
{

class UdpSocket
{
public:
    static constexpr int FLAG_AF_SPEC = 1 << 1;
    static constexpr int FLAG_AF_SPEC6 = 1 << 2;

    static constexpr int FLAG_TRUNC = 1 << 3;
    static constexpr int FLAG_PKI_ENABLED = 1 << 4;
    static constexpr int FLAG_ECN_ENABLED = 1 << 5;

    static constexpr int FLAG_READABLE = 1 << 6;
    static constexpr int FLAG_WRITABLE = 1 << 7;

    static constexpr int FLAG_ECN_SHIFT = 8;
    static constexpr int FLAG_ECN_MASK = 3 << FLAG_ECN_SHIFT;

    struct Packet
    {
        sockaddr_storage *src = nullptr;
        sockaddr_storage *dest = nullptr;
        std::span<iovec> vec;
        int dataLen = 0;
        int flag = 0;
    };

    struct BatchSendMsg {
        UdpSocket &socket;
        std::array<Packet, 64> buffer;
        size_t bufSize = 0;

        NO_COPY(BatchSendMsg)

        explicit BatchSendMsg(UdpSocket &socket): socket(socket) {
        }

        ~BatchSendMsg() {
            flush();
        }

        Packet *pushBack(const Packet &packet) {
            if (bufSize >= buffer.size()) {
                flush();
            }
            if (bufSize >= buffer.size()) {
                return nullptr;
            }
            buffer[bufSize] = packet;
            return &buffer[bufSize ++];
        }

        ssize_t flush() {
            if (bufSize == 0) {
                return 0;
            }
            auto num = socket.sendTo({ buffer.data(), bufSize });
            if (num > 0) {
                if (static_cast<size_t>(num) < bufSize) {
                    std::move(buffer.begin() + num, buffer.begin() + bufSize, buffer.begin());
                }
                bufSize -= num;
            }
            return num;
        }
    };

private:
    static void deleteUvPoll(uv_poll_t *poll) {
        if (poll == nullptr) {
            return;
        }
        uv_close(reinterpret_cast<uv_handle_t*>(poll), [](auto handle) {
            delete handle;
        });
    }

    uv_os_sock_t mFd {};
    std::unique_ptr<uv_poll_t, decltype(&deleteUvPoll)> mPoll { nullptr, deleteUvPoll };
    std::function<void(int flag)> mCallback;

    sockaddr_storage mBindAddress {};

    int32_t mFlag = 0;

    void closeSocket();
    int initSocket(int family);

public:
    explicit UdpSocket() = default;
    ~UdpSocket() noexcept { close(); }

    NO_COPY(UdpSocket)

    int bind(const sockaddr_storage &local);
    int getLocalAddress(sockaddr_storage *out);
    int connect(const sockaddr_storage &remote);

    int getLocalPort() {
        sockaddr_storage local {};
        if (auto ret = getLocalAddress(&local); ret < 0) {
            return ret;
        }
        return Net::portOf(local);
    }

    int setSocketBuffSize(int bufSize);
//    int setGsoEnabled(bool enabled);
//    int setGroEnabled(bool enabled);
    int setEcnEnabled(bool enabled);
    int setNonBlocking(bool nonBlocking);
    int setReuseAddr(bool reuse);
    int setMtuDiscoverEnabled(bool enabled);
    int setPkiInfoEnabled(bool enabled);
    int setRxqOvflEnabled(bool enabled);

    ssize_t sendTo(std::span<Packet> packets);
    ssize_t recvFrom(std::span<Packet> packets);

    int start(uv_loop_t *loop, int flags, std::function<void(int)> callback) {
        mCallback = std::move(callback);

        if (mPoll == nullptr) {
            mPoll.reset(new uv_poll_t);
            mPoll->data = this;
            if (auto ret = uv_poll_init_socket(loop, mPoll.get(), mFd); ret < 0) {
                LOGE("failed to init uv_poll_t: '%d'", ret);
                return ret;
            }
        }
        return start(flags);
    }

    int start(int flags) {
        if (mPoll == nullptr) {
            return -1;
        }
        uv_poll_cb wrapper = [](uv_poll_t* handle, int status, int events) {
//            LOGD("uv_poll_start callback: status='(%s)%d', events='%d'", uv_err_name(status), status, events);
            auto self = static_cast<UdpSocket*>(handle->data);
            if (status != 0) {
                int error = 0;
                socklen_t errlen = sizeof(error);
                getsockopt(self->mFd, SOL_SOCKET, SO_ERROR, &error, &errlen);
                LOGE("sock err:'%d'", error);
                return;
            }
            int flag = 0;
            if ((events & UV_READABLE)) flag |= FLAG_READABLE;
            if ((events & UV_WRITABLE)) flag |= FLAG_WRITABLE;

            if (self->mCallback) {
                self->mCallback(flag);
            }
        };

        int events = 0;
        if ((flags & FLAG_READABLE)) events |= UV_READABLE;
        if ((flags & FLAG_WRITABLE)) events |= UV_WRITABLE;
        return uv_poll_start(mPoll.get(), events, wrapper);
    }

    int stop() { return uv_poll_stop(mPoll.get()); }

    void close() {
        if (mPoll != nullptr) {
            stop();
            mPoll = nullptr;
        }
        closeSocket();
        bzero(&mBindAddress, sizeof(mBindAddress));
        mFlag = 0;
        mFd = { };
    }

    [[nodiscard]]
    int family() const noexcept {
        if ((mFlag & FLAG_AF_SPEC)) return AF_INET;
        if ((mFlag & FLAG_AF_SPEC6)) return AF_INET6;
        return AF_UNSPEC;
    }
};
}

#endif // HYSBURG_UDPSOCKET_H