
#ifndef HYSBURG_LOG_HPP
#define HYSBURG_LOG_HPP

#include <cstdio>
#include <ctime>
#include <chrono>
#include <cstring>
#include <cerrno>
#include <string>

#ifndef __FILE_NAME__
#define __FILE_NAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#define LOGI(fmt, ...) fprintf(stderr, "%s %llu I/LOG: %s(%d):" fmt "\n", Log::formatTime(), Log::threadId(), __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define LOGD(fmt, ...) fprintf(stderr, "%s %llu D/LOG: %s(%d):" fmt "\n", Log::formatTime(), Log::threadId(), __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stderr, "%s %llu W/LOG: %s(%d):" fmt "\n", Log::formatTime(), Log::threadId(), __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "%s %llu E/LOG: %s(%d):" fmt "\n", Log::formatTime(), Log::threadId(), __FILE_NAME__, __LINE__, ##__VA_ARGS__)
#define PLOGE(fmt, ...) do { LOGE(fmt "\nerrno=%d(%s)", ##__VA_ARGS__, errno, strerror(errno)); std::terminate(); } while (0)


struct Log
{
    static uint64_t threadId() {
        // pthread_self() 非常慢，pthread_key 快很多，thread_local 最快
        thread_local pthread_t self = pthread_self();
        return reinterpret_cast<uint64_t>(self);
    }

    static uint64_t currentTimeMillis()
    {
        auto now = std::chrono::system_clock::now();
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
        return now_ms.count();
    }

    static const char *formatTime()
    {
        thread_local char sTimeStr[64] {};

        // 获取当前时间（包括毫秒）
        auto now = std::chrono::system_clock::now();
        auto now_as_time_t = std::chrono::system_clock::to_time_t(now);
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        // 转换为本地时间
        std::tm *local_tm = std::localtime(&now_as_time_t);

        // 使用strftime进行时间格式化
        char buffer[32] {};
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", local_tm);

        // 将毫秒添加到格式化的字符串
        std::snprintf(sTimeStr, sizeof(sTimeStr), "%s.%03ld",
                      buffer, static_cast<long int>(now_ms.count()));
        return sTimeStr;
    }

    static void print(const char *msg, size_t msgLen)
    {
        while (msgLen > 0 && msg[msgLen - 1] <= ' ') {
            msgLen -= 1;
        }
        println(msg, msgLen);
    }

    static void println(const char *msg, size_t msgLen)
    {
        if (msgLen <= 0) {
            return;
        }
        if (msg[msgLen] == '\0') {
            LOGI("%s", msg);
            return;
        }
        char buff[256];
        auto bytes = std::min(sizeof(buff) - 1, msgLen);
        memcpy(buff, msg, bytes);
        buff[bytes] = '\0';
        LOGI("%s", buff);
        msgLen -= bytes;
        msg += bytes;

        if (msgLen > 0) {
            fwrite(msg, 1, msgLen, stderr);
        }
    }
};

#endif //HYSBURG_LOG_HPP