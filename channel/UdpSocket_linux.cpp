#include "UdpSocket.h"
#include "UdpSocket_unix.hpp"

using namespace hysburg;

int UdpSocket::setRxqOvflEnabled(bool enabled) {
    return SET_SOCKET_OPTION(mFd, SOL_SOCKET, SO_RXQ_OVFL, enabled ? 1 : 0);
}

int UdpSocket::setMtuDiscoverEnabled(bool enabled) {
    auto ret = -1;
    switch (mFamily) {
        case AF_INET:
            ret = SET_SOCKET_OPTION(mFd, IPPROTO_IP, IP_MTU_DISCOVER, enabled ? IP_PMTUDISC_PROBE : IP_PMTUDISC_DONT);
            break;
        case AF_INET6:
            ret = SET_SOCKET_OPTION(mFd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, enabled ? IPV6_PMTUDISC_PROBE : IPV6_PMTUDISC_DONT);
            break;
    }
    return ret;
}
