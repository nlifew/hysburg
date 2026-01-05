
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#include "Log.hpp"
#include "UdpSocket.h"
#include "UdpSocket_unix.hpp"

using namespace hysburg;

int UdpSocket::setRxqOvflEnabled(bool) {
    (void) this;
    return -1;
}

int UdpSocket::setMtuDiscoverEnabled(bool enabled) {
    (void) this;
    auto ret = -1;
    switch (mFamily) {
        case AF_INET:
            ret = SET_SOCKET_OPTION(mFd, IPPROTO_IP, IP_DONTFRAG, enabled ? 1 : 0);
            break;
        case AF_INET6:
            ret = SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_DONTFRAG, enabled ? 1 : 0);
            break;
    }
    return ret;
}

//int UdpSocket::setGsoEnabled(bool) {
//    (void) this;
//    return -1;
//}
//
//int UdpSocket::setGroEnabled(bool) {
//    (void) this;
//    return -1;
//}


/**
 * libuv 的实现也是参考的这里：
 * https://github.com/apple/darwin-xnu/blob/main/bsd/sys/socket.h
 */
struct msghdr_x {
    msghdr msghdr;
    size_t          msg_datalen;    /* byte length of buffer in msg_iov */
};

extern "C" ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
extern "C" ssize_t recvmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);

struct CMsgBuf {
    char data[128];
};

static constexpr int PACKET_MAX_SIZE = 64;

ssize_t UdpSocket::recvFrom(UdpSocket::Packet *packets, int len) {
    std::array<CMsgBuf, PACKET_MAX_SIZE> cmsgBuf;
    std::array<msghdr_x, PACKET_MAX_SIZE> msghdrBuf;

    len = std::min(len, PACKET_MAX_SIZE);
    for (int i = 0; i < len; i ++) {
        msghdrBuf[i].msghdr = {
                .msg_name = packets[i].src,
                .msg_namelen = sizeof(sockaddr_storage),
                .msg_iov = packets[i].vec,
                .msg_iovlen = packets[i].vecLen,
                .msg_control = cmsgBuf[i].data,
                .msg_controllen = sizeof(cmsgBuf[i].data),
                .msg_flags = 0,
        };
        msghdrBuf[i].msg_datalen = 0;
    }

    auto port = getLocalPort();
    auto ret = ::recvmsg_x(mFd, msghdrBuf.data(), len, MSG_DONTWAIT);

    for (int i = 0; i < ret; i ++) {
        packets[i].ecn = -1;
        packets[i].flag = 0;
        packets[i].dataLen = static_cast<int>(msghdrBuf[i].msg_datalen);

        auto dest = packets[i].dest;
        if (dest != nullptr) {
            dest->ss_family = AF_UNSPEC;
        }

        auto msg = &msghdrBuf[i].msghdr;
        for (auto* cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (packets[i].ecn == -1) {
                UnixUdpSocket::recvEcn(cmsg, &packets[i].ecn);
            }
            if (dest != nullptr && dest->ss_family == AF_UNSPEC) {
                UnixUdpSocket::recvDestAddr(cmsg, dest, port);
            }
        }

        auto flag = msg->msg_flags;
        if ((flag & FLAG_TRUNC)) { packets[i].flag |= FLAG_TRUNC; }
    }
    return ret;
}


ssize_t UdpSocket::sendTo(UdpSocket::Packet *packets, int len) {
    std::array<CMsgBuf, PACKET_MAX_SIZE> cmsgBuf;
    std::array<msghdr_x, PACKET_MAX_SIZE> msghdrBuf;

    len = std::min(len, PACKET_MAX_SIZE);
    for (int i = 0; i < len; ++i) {
        msghdrBuf[i].msg_datalen = 0;
        auto *msg = &msghdrBuf[i].msghdr;
        *msg = {
                .msg_name = packets[i].dest,
                .msg_namelen = Net::getSockLen(packets[i].dest->ss_family),
                .msg_iov = packets[i].vec,
                .msg_iovlen = packets[i].vecLen,
                .msg_control = cmsgBuf[i].data,
                .msg_controllen = 0,
                .msg_flags = 0,
        };
        if ((mFlag & FLAG_ECN_ENABLED) != 0) {
            UnixUdpSocket::sendEcn(msg, mFamily, packets[i].ecn & 0x03);
        }
        if (packets[i].src != nullptr && (mFlag & FLAG_PKI_ENABLED) != 0) {
            UnixUdpSocket::sendSourceAddr(msg, packets[i].src);
        }
        if (msg->msg_controllen <= 0) {
            msg->msg_control = nullptr;
            msg->msg_controllen = 0;
        }
        if (msg->msg_controllen > sizeof(CMsgBuf)) {
            LOGE("msg_controllen > sizeof(CMsgBuf), %d, %zu", msg->msg_controllen, sizeof(CMsgBuf));
            return -1;
        }
    }
    auto ret = ::sendmsg_x(mFd, msghdrBuf.data(), len, MSG_DONTWAIT);
    for (int i = 0; i < ret; i ++) {
        packets[i].flag = msghdrBuf[i].msghdr.msg_flags;
        packets[i].dataLen = static_cast<int>(msghdrBuf[i].msg_datalen);
    }
    return ret;
}
