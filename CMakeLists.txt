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
    add_library(
        dns-tools-crypto
            src/crypto/hash/digest.cpp
            src/crypto/sign/sign.cpp
            src/crypto/verify/verify.cpp
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

# DNS library
    add_library(
        dns-tools-dns
            src/dns/rr.cpp
            src/dns/wire_format.cpp
            src/dns/zone_parser.cpp
    )

    target_include_directories(
        dns-tools-dns
            PUBLIC
                src/dns
    )

    target_link_libraries(
        dns-tools-dns
            PRIVATE
                dns-tools-crypto
    )

# Context library
    add_library(
        dns-tools-context
            src/context/context.cpp
    )

    target_include_directories(
        dns-tools-context
            PUBLIC
                src/context
    )

    target_link_libraries(
        dns-tools-context
            PRIVATE
                dns-tools-crypto
    )

# CLI library
    add_library(
        dns-tools-cli
            src/cli/sign/sign_command.cpp
            src/cli/verify/verify_command.cpp
            src/cli/digest/digest_command.cpp
            src/context/context.cpp
            src/crypto/hash/digest.cpp
            src/crypto/sign/sign.cpp
            src/crypto/verify/verify.cpp
    )

    target_include_directories(
        dns-tools-cli
            PUBLIC
                src/cli
                src/context
                src/crypto
                src/dns
    )
    
    target_link_libraries(
        dns-tools-cli
            PRIVATE
                CLI11::CLI11
                dns-tools-crypto
                dns-tools-dns
    )


add_executable(dns-tools src/main.cpp)

target_link_libraries(
    dns-tools
    PRIVATE
        dns-tools-cli
        dns-tools-crypto
)

target_include_directories(
    dns-tools
    PUBLIC
        "${PROJECT_SOURCE_DIR}"
)

