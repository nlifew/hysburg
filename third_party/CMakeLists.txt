
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
FetchContent_MakeAvailable(libuv)


FetchContent_Declare(
        boringssl
        URL
        "https://github.com/google/boringssl/archive/refs/tags/0.20251124.0.zip"
)
set(BUILD_TESTING OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(boringssl)
