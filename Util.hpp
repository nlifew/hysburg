
#ifndef HYSBURG_UTIL_HPP
#define HYSBURG_UTIL_HPP

#include <string>
#include <random>
#include <exception>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "Log.hpp"

#define NO_COPY(X) \
    X(const X &) = delete; \
    X &operator=(const X &) = delete;

#define LIKELY(x)       __builtin_expect(!!(x), 1)
#define UNLIKELY(x)     __builtin_expect(!!(x), 0)

#define CHECK(COND, FMT, ...) \
    if (UNLIKELY(!(COND))) {     \
        PLOGE(FMT, ##__VA_ARGS__); \
    }

namespace hysburg
{

struct Times
{
    static uint64_t currentTimeMillis() noexcept
    {
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
        return now_ms.count();
    }
};

struct Numbers
{
    template<size_t N>
    static size_t align(size_t in)
    {
        return ((in - 1) | (N - 1)) + 1;
    }

    template<typename T>
    static std::enable_if_t<sizeof(T) == 1, T> reverseByte(T value) noexcept
    {
        return value;
    }

    template<typename T>
    static std::enable_if_t<sizeof(T) == 2, T> reverseByte(T value) noexcept
    {
        auto *ptr = reinterpret_cast<uint8_t *>(&value);
        std::swap(ptr[0], ptr[1]);
        return value;
    }

    template <typename T>
    static std::enable_if_t<sizeof(T) == 3, T> reverseByte(T value) noexcept
    {
        auto *ptr = reinterpret_cast<uint8_t *>(&value);
        std::swap(ptr[0], ptr[2]);
        return value;
    }

    template<typename T>
    static std::enable_if_t<sizeof(T) == 4, T> reverseByte(T value) noexcept
    {
        auto *ptr = reinterpret_cast<uint8_t *>(&value);
        std::swap(ptr[0], ptr[3]);
        std::swap(ptr[1], ptr[2]);
        return value;
    }

    template<typename T>
    static std::enable_if_t<sizeof(T) == 8, T> reverseByte(T value) noexcept
    {
        auto *ptr = reinterpret_cast<uint8_t *>(&value);
        std::swap(ptr[0], ptr[7]);
        std::swap(ptr[1], ptr[6]);
        std::swap(ptr[2], ptr[5]);
        std::swap(ptr[3], ptr[4]);
        return value;
    }

    static std::default_random_engine &getRandomEngine()
    {
        static std::default_random_engine e(std::random_device().operator()());
        return e;
    }

    template<typename T>
    static T randomInt() {
        std::uniform_int_distribution<T> dis;
        return dis(getRandomEngine());
    }

    template<typename T>
    static T randomInt(T min, T max) {
        auto value = randomInt<T>();
        return value % (max - min + 1) + min;
    }

    static void writeRandom(void *out, size_t len)
    {
        auto ptr = (uint8_t *) out;

        while (len >= 8) {
            *((uint64_t *) ptr) = randomInt<uint64_t>();
            len -= 8;
            ptr += 8;
        }
        while (len > 0) {
            *ptr = randomInt<uint8_t>();
            len -= 1;
            ptr += 1;
        }
    }
};

struct Net
{
    static bool isIpv4(const char *str) noexcept
    {
        sockaddr_in addr {};
        return inet_pton(AF_INET, str, &addr) == 0;
    }

    static bool isIpv6(const char *str) noexcept
    {
        sockaddr_in6 addr {};
        return inet_pton(AF_INET6, str, &addr) == 0;
    }

    static bool equals(const sockaddr_storage *p, const sockaddr *q) noexcept
    {
        if (p == nullptr || q == nullptr) {
            return false;
        }
        if (p->ss_family != q->sa_family) {
            return false;
        }
        switch (p->ss_family) {
            case AF_INET: {
                auto *pIn = reinterpret_cast<const sockaddr_in*>(p);
                auto *qIn = reinterpret_cast<const sockaddr_in*>(q);
                return memcmp(&pIn->sin_addr, &qIn->sin_addr, sizeof(pIn->sin_addr)) == 0;
            }
            case AF_INET6: {
                auto *pIn6 = reinterpret_cast<const sockaddr_in6*>(p);
                auto *qIn6 = reinterpret_cast<const sockaddr_in6*>(q);
                return memcmp(&pIn6->sin6_addr, &qIn6->sin6_addr, sizeof(pIn6->sin6_addr)) == 0;
            }
        }
        return false;
    }

    static int copy(sockaddr_storage *out, const sockaddr *in) noexcept
    {
        if (in == nullptr) {
            return -1;
        }
        memcpy(out, in, getSockLen(in->sa_family));
        return 0;
    }

    static socklen_t getSockLen(int family) noexcept
    {
        switch (family) {
            case AF_INET: return sizeof(sockaddr_in);
            case AF_INET6: return sizeof(sockaddr_in6);
            default: return 0;
        }
    }

    static int portOf(const sockaddr_storage &socks)
    {
        if (socks.ss_family == AF_INET) {
            auto *peer4 = (struct sockaddr_in*) &socks;
            return ntohs(peer4->sin_port);
        }
        if (socks.ss_family == AF_INET6) {
            auto *peer6 = (struct sockaddr_in6*) &socks;
            return ntohs(peer6->sin6_port);
        }
        return 0;
    }

    static std::string toString(const sockaddr *addr)
    {
        if (addr->sa_family == AF_INET) {
            auto *peer4 = (struct sockaddr_in*) addr;
            char str[64];
            inet_ntop(AF_INET, &peer4->sin_addr, str, sizeof(str));
            return std::string(str) + ":" + std::to_string(ntohs(peer4->sin_port));
        }
        if (addr->sa_family == AF_INET6) {
            auto *peer6 = (struct sockaddr_in6*) addr;
            char str[256];
            inet_ntop(AF_INET6, &peer6->sin6_addr, str, sizeof(str));
            return std::string(str) + ":" + std::to_string(ntohs(peer6->sin6_port));
        }
        return "";
    }

    static std::string stringOf(const sockaddr *socks)
    {
        return toString(socks);
    }

    static std::string stringOf(const sockaddr_storage *socks)
    {
        return toString((sockaddr *) socks);
    }

    static std::string stringOf(const sockaddr_storage &socks)
    {
        return toString((sockaddr *) &socks);
    }
};

struct Strings
{
    static char *unsafeToUpper(char *str, size_t len) noexcept
    {
        char *ret = str;
        // bin('A')     = 0100 0001
        // bin('a')     = 0110 0001
        // bin(0xDF)    = 1101 1111
        // 本质上就是和 0xDF 做与运算
        uint64_t mask = 0xDFDFDFDFDFDFDFDF;
        while (len >= 8) {
            *(uint64_t *) str &= mask;
            len -= 8;
            str += 8;
        }
        while (len > 0) {
            *(uint8_t *) str &= 0xDF;
            len -= 1;
            str += 1;
        }
        return ret;
    }

    static char *unsafeToLower(char *str, size_t len) noexcept
    {
        char *ret = str;
        // bin('A')     = 0100 0001
        // bin('a')     = 0110 0001
        // bin(0x20)    = 0010 0000
        // 本质上就是和 0x20 做或运算
        uint64_t mask = 0x2020202020202020;
        while (len >= 8) {
            *(uint64_t *) str |= mask;
            len -= 8;
            str += 8;
        }
        while (len > 0) {
            *(uint8_t *) str |= 0x20;
            len -= 1;
            str += 1;
        }
        return ret;
    }

    static char *toUpper(char *str, size_t len) noexcept
    {
        for (size_t i = 0; i < len; ++i) {
            str[i] = (char) std::toupper(str[i]);
        }
        return str;
    }


//    static std::string randomString(size_t len) noexcept
//    {
//        std::vector<unsigned char> vec(len / 4 * 3 + 4);
//        Numbers::writeRandom(vec.data(), vec.size());
//        auto ret = base64_encode(vec.data(), vec.size());
//        ret.resize(len);
//        return ret;
//    }

    static int toInt(const std::string &s) noexcept
    {
        if (s.empty()) {
            return 0;
        }
        return std::stoi(s);
    }
};

}

#endif // HYSBURG_UTIL_HPP
