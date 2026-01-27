cmake_minimum_required(VERSION 3.10)

project(
    dns-tools
    VERSION 0.1
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

find_package(CLI11 REQUIRED)
find_package(OpenSSL REQUIRED)

# Crypto library
#[[
    add_library(
        dns-tools-crypto
    )

    target_include_directories(
        dns-tools-crypto
            PUBLIC
                src/crypto
    )

    target_link_libraries(
        dns-tools-crypto
            PRIVATE
                OpenSSL::Crypto
    )
]]
# CLI library
    add_library(
        dns-tools-cli
            src/cli/sign/sign_command.cpp
            src/cli/verify/verify_command.cpp
            src/cli/digest/digest_command.cpp
    )

    target_include_directories(
        dns-tools-cli
            PUBLIC
                src/cli
                src/context
                src/crypto
    )
    
    target_link_libraries(
        dns-tools-cli
            PRIVATE
                # dns-tools-crypto
                CLI11::CLI11
    )


add_executable(dns-tools src/main.cpp)

target_link_libraries(
    dns-tools
    PRIVATE
        dns-tools-cli
        # dns-tools-crypto
)

target_include_directories(
    dns-tools
    PUBLIC
        "${PROJECT_SOURCE_DIR}"
)

