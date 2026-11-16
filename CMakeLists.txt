cmake_minimum_required(VERSION 3.16)
project(sapper VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

add_executable(sapper
    src/main.cpp
    src/proto.cpp
    src/tls_util.cpp
    src/socks.cpp
    src/server.cpp
    src/agent.cpp
)

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(sapper PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

install(TARGETS sapper RUNTIME DESTINATION bin)
