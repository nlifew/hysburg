
include(FetchContent)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

FetchContent_Declare(
        llhttp
        URL
        "https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.3.0.tar.gz"
)

set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(BUILD_STATIC_LIBS ON CACHE INTERNAL "")
FetchContent_MakeAvailable(llhttp)

FetchContent_Declare(
        libuv
        URL
        "https://github.com/libuv/libuv/archive/refs/tags/v1.51.0.zip"
)
set(LIBUV_BUILD_SHARED OFF CACHE INTERNAL "")
set(BUILD_TESTING OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(libuv)


FetchContent_Declare(
        boringssl
        URL
        "https://github.com/google/boringssl/archive/refs/tags/0.20251124.0.zip"
)
FetchContent_MakeAvailable(boringssl)

FetchContent_Declare(
        ngtcp2
        URL
        "https://github.com/ngtcp2/ngtcp2/archive/refs/tags/v1.21.0.zip"
)
set(ENABLE_LIB_ONLY ON CACHE INTERNAL "")
set(ENABLE_SHARED_LIB OFF CACHE INTERNAL "")
set(ENABLE_OPENSSL OFF CACHE INTERNAL "")
set(ENABLE_BORINGSSL ON CACHE INTERNAL "")
set(BORINGSSL_INCLUDE_DIR "${boringssl_SOURCE_DIR}/include" CACHE INTERNAL "")
# 通过覆盖 HAVE_OPENSSL_IS_BORINGSSL 变量强制绕过 check_cxx_symbol_exists 检查，
# 因为 cmake 在 configure 时还没有 ssl 和 crypto 库
#set(BORINGSSL_LIBRARIES "ssl;crypto" CACHE INTERNAL "")
set(HAVE_OPENSSL_IS_BORINGSSL ON CACHE INTERNAL "Bypass BoringSSL configure-time check")

FetchContent_MakeAvailable(ngtcp2)
