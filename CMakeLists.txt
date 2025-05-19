cmake_minimum_required(VERSION 3.25.1)
project(hysburg)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_INCLUDE_CURRENT_DIR ON)

include_directories(/opt/homebrew/include)
link_directories(/opt/homebrew/lib)

include_directories(/usr/local/include)
link_directories(/usr/local/lib)

add_subdirectory(test)

add_subdirectory(third_party)
add_compile_options("-Wall" "-Wextra" "-Wno-unused-parameter")

add_library(
        runtime
        STATIC
        channel/Channel.cpp
)
target_link_libraries(
        runtime
        uv
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
