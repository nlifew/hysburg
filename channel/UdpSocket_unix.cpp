
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#include <uv.h>

#include "Log.hpp"
#include "UdpSocket.h"
#include "UdpSocket_unix.hpp"

using namespace hysburg;

int UdpSocket::initSocket(int family) {
    mFamily = family;
    if ((mFd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP)) <= 0) {
        return -1;
    }
    if (family == AF_INET6) {
        SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
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

    socklen_t len = Net::getSockLen(local.ss_family);
    if (len <= 0) {
        LOGE("failed to get socklen of '%d'", mFd);
        return -1;
    }

    auto ret = ::bind(mFd, reinterpret_cast<const sockaddr*>(&local), len);
    if (ret < 0) {
        LOGE("::bind(%d)='%d', errno='%d'", mFd, ret, errno);
        return -1;
    }
    if ((ret = ::getsockname(mFd, reinterpret_cast<sockaddr*>(&mBindAddress), &len)) < 0) {
        LOGE("::getsockname(%d)='%d', errno='%d'", mFd, ret, errno);
        return -1;
    }
    mFlag |= FLAG_BIND;
    mLocalPort = Net::portOf(mBindAddress);
    return ret;
}

int UdpSocket::getLocalAddress(sockaddr_storage *out) {
    if ((mFlag & FLAG_BIND) != 0) {
        memcpy(out, &mBindAddress, sizeof(mBindAddress));
        return 0;
    }
    socklen_t len = sizeof(sockaddr_storage);
    auto ret = getsockname(mFd, (sockaddr *) out, &len);
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
    switch (mFamily) {
        case AF_INET:
            ret = SET_SOCKET_OPTION(mFd, IPPROTO_IP, IP_PKTINFO, enabled ? 1 : 0);
            break;
        case AF_INET6:
            ret = SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_RECVPKTINFO, enabled ? 1 : 0);
            break;
    }
    if (ret == 0) {
        mFlag = enabled ? (mFlag | FLAG_PKI_ENABLED) : (mFlag & ~FLAG_PKI_ENABLED);
    }
    return ret;
}

int UdpSocket::setEcnEnabled(bool enabled) {
    (void) this;
    auto ret = 0;
    switch (mFamily) {
        case AF_INET:
            ret |= SET_SOCKET_OPTION(mFd, IPPROTO_IP, IP_RECVTOS, enabled ? 1 : 0);
            ret |= SET_SOCKET_OPTION(mFd, IPPROTO_IP, IP_TOS, 0); // [1]
            break;
        case AF_INET6:
            ret |= SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_RECVTCLASS, enabled ? 1 : 0);
            ret |= SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_TCLASS, 0); // [1]
            break;
        default:
            return -1;
    }
    // [1]. 发送 ecn 时，setsockopt() 不是必须的，而是为 socket 设置一个默认的 ecn 值。
    // 当 cmsghdr 中没有显式设置 ecn 时，就会用这个默认值。
    // 但是接收 ecn 时必须设置为 1，否则内核会剥离掉这些信息
    if (ret == 0) {
        mFlag = enabled ? (mFlag | FLAG_ECN_ENABLED) : (mFlag & ~FLAG_ECN_ENABLED);
    }
    return ret;
}

