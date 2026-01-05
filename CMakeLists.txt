cmake_minimum_required(VERSION 3.25.1)
project(hysburg)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_INCLUDE_CURRENT_DIR ON)

add_subdirectory(test)

add_subdirectory(third_party)
add_compile_options(
        "-Wall"
        "-Wextra"
        "-Werror"
        "-pthread"
        "-fno-exceptions"
        "-Wno-deprecated-declarations"
#        "-fsanitize=address"
#        "-fno-omit-frame-pointer"
#        "-fsanitize=thread"
)
add_link_options(
        "-pthread"
#        "-fsanitize=address"
#        "-fsanitize=thread"
)

set(RUNTIME_SOURCES
        channel/Channel.cpp
        channel/TLSContext.cpp
        channel/UdpSocket_unix.cpp
)
if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    list(APPEND RUNTIME_SOURCES channel/UdpSocket_osx.cpp)
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
    list(APPEND RUNTIME_SOURCES channel/UdpSocket_linux.cpp)
endif ()

add_library(
        runtime
        STATIC
        ${RUNTIME_SOURCES}
)
target_link_libraries(
        runtime
        uv_a
#        decrepit
        ssl
        crypto
        llhttp_static
)

add_executable(
        hysburg
        main2.cpp
)

target_link_options(
        hysburg
        PUBLIC
        "-pthread"
)

target_link_libraries(
        hysburg
        runtime
)
