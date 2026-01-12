
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
