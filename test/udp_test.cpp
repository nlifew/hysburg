#include <cassert>

#include "channel/UdpSocket.h"
#include "channel/EventLoop.hpp"

using namespace hysburg;

void sendUdp(UdpSocket &udpSocket, UdpSocket::Packet *packets, int size) {
    std::vector<std::string> textList = {
            "one", "two", "three", "four", "fine", "six", "seven", "eight", "nine", "ten",
    };
    for (int i = 0; i < size; i ++) {
        uv_ip4_addr("127.0.0.1", 4016, (sockaddr_in *) packets[i].dest);

        packets[i].ecn = (i) & 3;

        const auto ioVec = packets[i].vec;
        const auto &text = textList[i % textList.size()];
        strcpy((char*) ioVec->iov_base, text.data());
        ioVec->iov_len = text.size();
    }
    auto ret = udpSocket.sendTo(packets, size);
    printf("send()='%ld', errno='%d(%s)'\n", ret, errno, strerror(errno));
}

static constexpr int SIZE = 16;

void recvUdp(UdpSocket &udpSocket, uv_loop_t *loop, UdpSocket::Packet *packets, int size) {
    static ssize_t allPacketSum = 0;

    auto ret = udpSocket.poll(loop, [&udpSocket, packets, size]() {
        for (int i = 0; i < size; i ++) {
            packets[i].vec->iov_len = 1500;
            bzero(packets[i].dest, sizeof(sockaddr_storage));
            bzero(packets[i].src, sizeof(sockaddr_storage));
        }
        auto ret = udpSocket.recvFrom(packets, size);
        LOGI("recv()='%ld', errno='%d(%s)'", ret, errno, strerror(errno));
        for (int i = 0; i < ret; i ++) {
            fprintf(stderr, "[%d/%ld]: '%s'->'%s', flag='%#08x', text='",
                    i + 1, ret,
                    Net::stringOf(packets[i].src).c_str(),
                    Net::stringOf(packets[i].dest).c_str(),
                    packets[i].flag);
            fwrite(packets[i].vec->iov_base, 1, packets[i].dataLen, stderr);
            fputs("'\n", stderr);
        }
        if (ret > 0 && (allPacketSum += ret) >= SIZE) {
            LOGI("all packets received, exit");
            exit(0);
        }
    });
    assert(ret == 0);
}

struct Payload {
    sockaddr_storage src;
    sockaddr_storage dest;
    iovec vec;
    char buff[1500];
};

static void bindPayload(UdpSocket::Packet *packet, Payload &payload) {
    packet->src = &payload.src;
    packet->dest = &payload.dest;
    packet->vec = &payload.vec;
    packet->vecLen = 1;
    packet->ecn = packet->flag = packet->dataLen = 0;

    payload.vec = {
            .iov_base = payload.buff,
            .iov_len = 0,
    };
}

static UdpSocket udpSocket;

static void doMain(uv_loop_t *loop) {
    assert(udpSocket.initSocket(AF_INET) == 0);

    udpSocket.setNonBlocking(true);
    udpSocket.setEcnEnabled(true);
    udpSocket.setPkiInfoEnabled(true);

    sockaddr_storage src {};
    uv_ip4_addr("0.0.0.0", 8443, (sockaddr_in*) &src);
    assert(udpSocket.bind(src) == 0);

    static UdpSocket::Packet packetList[SIZE];
    static Payload payloadList[SIZE];
    for (int i = 0; i < SIZE; i ++) {
        bindPayload(&packetList[i], payloadList[i]);
    }
    recvUdp(udpSocket, loop, packetList, SIZE);
    sendUdp(udpSocket, packetList, SIZE);
}

int main() {
    auto eventLoop = std::make_shared<EventLoop>();
    eventLoop->post([loop = eventLoop->handle()]() {
        doMain(loop);
    });
    eventLoop->loop();
    return 0;
}