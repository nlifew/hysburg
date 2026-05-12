
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#include <unistd.h>
#include <uv.h>

#include "Log.hpp"
#include "UdpSocket.h"
#include "UdpSocket_unix.hpp"

using namespace hysburg;

int UdpSocket::initSocket(int family) {
    if ((mFd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP)) <= 0) {
        return -1;
    }
    switch (family) {
        case AF_INET:
            mFlag |= FLAG_AF_SPEC;
            break;
        case AF_INET6:
            mFlag |= FLAG_AF_SPEC6;
            SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
            break;
        default:
            return -1;
    }
    return 0;
}

void UdpSocket::closeSocket() {
    if (mFd > 0) {
        ::close(mFd);
        mFd = -1;
    }
}

int UdpSocket::bind(const sockaddr_storage &local) {
    (void) this;

    if (mFd <= 0 && initSocket(local.ss_family) < 0) {
        return -1;
    }
    socklen_t len = Net::getSockLen(local.ss_family);
    if (len <= 0) {
        LOGE("failed to get socklen of '%d'", mFd);
        return -2;
    }
    auto ret = ::bind(mFd, reinterpret_cast<const sockaddr*>(&local), len);
    if (ret < 0) {
        LOGE("::bind(%d)='%d', errno='%d'", mFd, ret, errno);
        return -3;
    }
    return 0;
}

int UdpSocket::connect(const sockaddr_storage &remote) {
    (void) this;

    if (mFd <= 0 && initSocket(remote.ss_family) < 0) {
        return -1;
    }
    socklen_t len = Net::getSockLen(remote.ss_family);
    if (len <= 0) {
        LOGE("failed to get socklen of '%d'", mFd);
        return -2;
    }
    auto ret = ::connect(mFd, reinterpret_cast<const sockaddr*>(&remote), len);
    if (ret < 0) {
        LOGE("::connect(%d)='%d', errno='%d'", mFd, ret, errno);
        return -3;
    }
    return 0;
}

int UdpSocket::getLocalAddress(sockaddr_storage *out) {
    (void) this;
    socklen_t len = sizeof(sockaddr_storage);
    auto ret = getsockname(mFd, reinterpret_cast<sockaddr*>(out), &len);
    return ret;
}


int UdpSocket::setReuseAddr(bool reuse) {
    (void) this;
    return SET_SOCKET_OPTION(mFd, SOL_SOCKET, SO_REUSEADDR, reuse ? 1 : 0);
}

int UdpSocket::setSocketBuffSize(int bufSize) {
    (void) this;
    auto ret = 0;
    ret |= SET_SOCKET_OPTION(mFd, SOL_SOCKET, SO_RCVBUF, bufSize);
    ret |= SET_SOCKET_OPTION(mFd, SOL_SOCKET, SO_SNDBUF, bufSize);
    return ret;
}

int UdpSocket::setNonBlocking(bool nonBlocking) {
    (void) this;
    auto ret = -1;
    if (auto flags = ::fcntl(mFd, F_GETFL, 0); flags >= 0) {
        ret = ::fcntl(mFd, F_SETFL, nonBlocking ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
    }
    return ret;
}

int UdpSocket::setPkiInfoEnabled(bool enabled) {
    (void) this;
    auto ret = -1;

    if ((mFlag & FLAG_AF_SPEC)) {
        ret = SET_SOCKET_OPTION(mFd, IPPROTO_IP, IP_PKTINFO, enabled ? 1 : 0);
    }
    if ((mFlag & FLAG_AF_SPEC6)) {
        ret = SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_RECVPKTINFO, enabled ? 1 : 0);
    }
    if (ret == 0) {
        mFlag = enabled ? (mFlag | FLAG_PKI_ENABLED) : (mFlag & ~FLAG_PKI_ENABLED);
    }
    return ret;
}

int UdpSocket::setEcnEnabled(bool enabled) {
    (void) this;
    auto ret = 0;

    if ((mFlag & FLAG_AF_SPEC)) {
        ret |= SET_SOCKET_OPTION(mFd, IPPROTO_IP, IP_RECVTOS, enabled ? 1 : 0);
        ret |= SET_SOCKET_OPTION(mFd, IPPROTO_IP, IP_TOS, 0); // [1]
    }
    if ((mFlag & FLAG_AF_SPEC6)) {
        ret |= SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_RECVTCLASS, enabled ? 1 : 0);
        ret |= SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_TCLASS, 0); // [1]
    }
    // [1]. 发送 ecn 时，setsockopt() 不是必须的，而是为 socket 设置一个默认的 ecn 值。
    // 当 cmsghdr 中没有显式设置 ecn 时，就会用这个默认值。
    // 但是接收 ecn 时必须设置为 1，否则内核会剥离掉这些信息
    if (ret == 0) {
        mFlag = enabled ? (mFlag | FLAG_ECN_ENABLED) : (mFlag & ~FLAG_ECN_ENABLED);
    }
    return ret;
}

#if __APPLE__
/**
 * libuv 的实现也是参考的这里：
 * https://github.com/apple/darwin-xnu/blob/main/bsd/sys/socket.h
 */
struct mmsghdr {
    msghdr msg_hdr;
    size_t msg_len;    /* byte length of buffer in msg_iov */
};

extern "C" ssize_t sendmsg_x(int s, const struct mmsghdr *msgp, u_int cnt, int flags);
extern "C" ssize_t recvmsg_x(int s, const struct mmsghdr *msgp, u_int cnt, int flags);

static inline ssize_t sendmmsg(int fd, mmsghdr *mmsg, u_int cnt, int flags) {
    return ::sendmsg_x(fd, mmsg, cnt, flags);
}
static inline ssize_t recvmmsg(int fd, mmsghdr *mmsg, u_int cnt, int flags, const timespec *) {
    return ::recvmsg_x(fd, mmsg, cnt, flags);
}
#endif


/**
 * 每次调用 recv/send，最多发送 64 个包
 */
static constexpr int PACKET_MAX_SIZE = 64;

/**
 * CMSG 最大设置为 128 字节
 */
struct CMsgBuf {
    char data[128];
};
// sizeof(in6_pktinfo): 存放 src、dest addr
// sizeof(int): 存放 ecn
static_assert(sizeof(CMsgBuf) >= sizeof(cmsghdr) + sizeof(in6_pktinfo) + sizeof(int) + 8);


ssize_t UdpSocket::recvFrom(std::span<Packet> packets) {
    std::array<mmsghdr, PACKET_MAX_SIZE> msghdrBuf; // NOLINT(*-pro-type-member-init)
    std::array<CMsgBuf, PACKET_MAX_SIZE> cmsgBuf;   // NOLINT(*-pro-type-member-init)

    if (packets.size() > PACKET_MAX_SIZE) {
        packets = packets.first(PACKET_MAX_SIZE);
    }

    for (size_t i = 0; i < packets.size(); i ++) {
        msghdrBuf[i].msg_hdr = {
                .msg_name = packets[i].src,
                .msg_namelen = sizeof(sockaddr_storage),
                .msg_iov = packets[i].vec.data(),
                .msg_iovlen = (int) packets[i].vec.size(),
                .msg_control = cmsgBuf[i].data,
                .msg_controllen = sizeof(cmsgBuf[i].data),
                .msg_flags = 0,
        };
        msghdrBuf[i].msg_len = 0;
    }

    auto port = getLocalPort();
    ssize_t ret;
    do {
        ret = ::recvmmsg(mFd, msghdrBuf.data(), packets.size(), MSG_DONTWAIT, nullptr);
    } while (ret == -1 && errno == EINTR);

    for (int i = 0; i < ret; i ++) {
        int ecn = -1;
        packets[i].flag = 0;
        packets[i].dataLen = static_cast<int>(msghdrBuf[i].msg_len);

        auto dest = packets[i].dest;
        if (dest != nullptr) {
            dest->ss_family = AF_UNSPEC;
        }

        auto msg = &msghdrBuf[i].msg_hdr;
        for (auto* cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (ecn == -1) {
                UnixUdpSocket::recvEcn(cmsg, &ecn);
            }
            if (dest != nullptr && dest->ss_family == AF_UNSPEC) {
                UnixUdpSocket::recvDestAddr(cmsg, dest, port);
            }
        }

        if ((msg->msg_flags & FLAG_TRUNC)) { packets[i].flag |= FLAG_TRUNC; }
        packets[i].flag |= ecn << FLAG_ECN_SHIFT;
    }
    return ret;
}

ssize_t UdpSocket::sendTo(std::span<Packet> packets) {
    (void) this;

    std::array<mmsghdr, PACKET_MAX_SIZE> msghdrBuf; // NOLINT(*-pro-type-member-init)
    std::array<CMsgBuf, PACKET_MAX_SIZE> cmsgBuf;   // NOLINT(*-pro-type-member-init)

    if (packets.size() > PACKET_MAX_SIZE) {
        packets = packets.first(PACKET_MAX_SIZE);
    }
    for (size_t i = 0; i < packets.size(); ++i) {
        // macOS sendmsg_x: msg_len 是 INPUT 字段（"byte length of buffer in msg_iov"），
        // 必须由调用方预填 iov 总长度，内核才知道本条消息发多少字节。
        // Linux sendmmsg: msg_len 是 OUTPUT 字段，此处预填会被内核覆写，无影响。
        msghdrBuf[i].msg_len = 0;
        for (auto &v : packets[i].vec) {
            msghdrBuf[i].msg_len += v.iov_len;
        }
        auto &msg = msghdrBuf[i].msg_hdr = {
                .msg_name = packets[i].dest,
                .msg_namelen = Net::getSockLen(packets[i].dest),
                .msg_iov = packets[i].vec.data(),
                .msg_iovlen = (int) packets[i].vec.size(),
                .msg_control = cmsgBuf[i].data,
                .msg_controllen = 0,
                .msg_flags = 0,
        };
        if ((mFlag & FLAG_ECN_ENABLED) != 0) {
            int ecn = (packets[i].flag & FLAG_ECN_MASK) >> FLAG_ECN_SHIFT;
            UnixUdpSocket::sendEcn(&msg, family(), ecn & 0x03);
        }
        if (packets[i].src != nullptr && (mFlag & FLAG_PKI_ENABLED) != 0) {
            UnixUdpSocket::sendSourceAddr(&msg, packets[i].src);
        }
        if (msg.msg_controllen <= 0) {
            msg.msg_control = nullptr;
            msg.msg_controllen = 0;
        }
        if (msg.msg_controllen > sizeof(CMsgBuf)) {
            LOGE("msg_controllen > sizeof(CMsgBuf), %zu, %zu",
                 (size_t) msg.msg_controllen, sizeof(CMsgBuf)
            );
            return -1;
        }
    }
    ssize_t ret;
    do {
        ret = ::sendmmsg(mFd, msghdrBuf.data(), packets.size(), MSG_DONTWAIT);
    } while (ret == -1 && errno == EINTR);

    for (int i = 0; i < ret; i ++) {
//        packets[i].flag = msghdrBuf[i].msg_hdr.msg_flags;
        // Linux: msg_len 由内核写入实际发送字节数。
        // macOS: msg_len 不被内核更新，仍是调用前预填的 iov 总长度。
        // UDP 是全量发送语义，二者结果一致，可以统一读取。
        packets[i].dataLen = static_cast<int>(msghdrBuf[i].msg_len);
    }
    return ret;
}
