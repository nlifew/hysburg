
include_directories(..)

add_executable(
        http_test
        http_test.cpp
)
target_link_libraries(
        http_test
        runtime
)
add_executable(
        tls_test
        tls_test.cpp
)
target_link_libraries(
        tls_test
        runtime
)

add_executable(
        socks5_test
        socks5_test.cpp
)
target_link_libraries(
        socks5_test
        runtime
)
