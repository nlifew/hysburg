
#ifndef HYSBURG_UDPSOCKET_UNIX
#define HYSBURG_UDPSOCKET_UNIX

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542 /* to use IPV6_PKTINFO */
#endif

namespace hysburg {

struct UnixUdpSocket {

    static cmsghdr *cmsgOf(msghdr *msg) {
        auto ptr = static_cast<char *>(msg->msg_control) + msg->msg_controllen;
        return reinterpret_cast<cmsghdr*>(ptr);
    }

    static int sendSourceAddr(msghdr *msg, const sockaddr_storage *addr) {
        auto cmsg = cmsgOf(msg);
        switch (addr->ss_family) {
            case AF_INET: {
                auto ipv4 = reinterpret_cast<const sockaddr_in*>(addr);
                in_pktinfo pktInfo {};
                pktInfo.ipi_spec_dst = ipv4->sin_addr;
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(pktInfo));
                memcpy(CMSG_DATA(cmsg), &pktInfo, sizeof(pktInfo));
                msg->msg_controllen += CMSG_SPACE(sizeof(pktInfo));
                return 0;
            }
            case AF_INET6: {
                auto ipv6 = reinterpret_cast<const sockaddr_in6*>(addr);
                in6_pktinfo pktInfo {};
                pktInfo.ipi6_addr = ipv6->sin6_addr;
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = CMSG_LEN(sizeof(pktInfo));
                memcpy(CMSG_DATA(cmsg), &pktInfo, sizeof(pktInfo));
                msg->msg_controllen += CMSG_SPACE(sizeof(pktInfo));
                return 0;
            }
        }
        return -1;
    }

    static int sendEcn(msghdr *msg, int family, int ecn) {
        // 直接 return 以后，默认的 ecn 取决于 setsockopt(IPPROTO_IP, IP_RECVTOS, value) 时 value 的值。
//        if ((ecn &= 3) == 0) {
//            return 0;
//        }

        auto cmsg = cmsgOf(msg);
        switch (family) {
            case AF_INET:
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_TOS;
                break;
            case AF_INET6:
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_TCLASS;
                break;
            default:
                return -1;
        }
        // ecn 的类型必须是 int 不能是 uint8_t。对于 ipv6，这个值必须为int；对于 ipv4，则取决于内核的兼容性
        // 如果内核不允许 uint8_t，则丢弃这个控制信息，导致 ecn 不生效
        cmsg->cmsg_len = CMSG_LEN(sizeof(ecn));
        memcpy(CMSG_DATA(cmsg), &ecn, sizeof(ecn));
        msg->msg_controllen += CMSG_SPACE(sizeof(ecn));
        return 0;
    }

    static int setSocketOption(int fd, int level, const char *levelName, int prop, const char *propName, int value) {
        if (auto ret = ::setsockopt(fd, level, prop, &value, sizeof(value)); ret < 0) {
            LOGE("failed: setsockopt(%d, %s, %s, %d)='%d', errno='%d'", fd, levelName, propName, value, ret, errno);
            return -1;
        }
        return 0;
    }

    static int recvDestAddr(const cmsghdr *cmsg, sockaddr_storage *out, int port) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            auto pkiInfo = reinterpret_cast<in_pktinfo*>(CMSG_DATA(cmsg));
            auto ipv4 = reinterpret_cast<sockaddr_in*>(out);
            ipv4->sin_family = AF_INET;
            ipv4->sin_addr = pkiInfo->ipi_addr;
            ipv4->sin_port = htons(port);
            return 0;
        }
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IPV6_PKTINFO) {
            auto pkiInfo = reinterpret_cast<in6_pktinfo*>(CMSG_DATA(cmsg));
            auto ipv6 = reinterpret_cast<sockaddr_in6*>(out);
            ipv6->sin6_family = AF_INET;
            ipv6->sin6_addr = pkiInfo->ipi6_addr;
            ipv6->sin6_port = htons(port);
            return 0;
        }
        return -1;
    }

    static int recvEcn(const cmsghdr *cmsg, int *ecn) {
        if (cmsg->cmsg_level == IPPROTO_IP && (cmsg->cmsg_type == IP_TOS || cmsg->cmsg_type == IP_RECVTOS)) {
            auto tos = *static_cast<uint8_t*>(CMSG_DATA(cmsg));
            *ecn = tos & 0x03;
            return 0;
        }
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_TCLASS) {
            auto tc = *static_cast<uint8_t*>(CMSG_DATA(cmsg));
            *ecn = tc & 0x03;
        }
        return -1;
    }
};
}

#define SET_SOCKET_OPTION(FD, LEVEL, PROP, VALUE) \
        UnixUdpSocket::setSocketOption(FD, LEVEL, #LEVEL, PROP, #PROP, VALUE)

#endif // HYSBURG_UDPSOCKET_UNIX