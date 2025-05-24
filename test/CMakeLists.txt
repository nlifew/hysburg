
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
