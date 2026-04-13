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

# Commons library
    add_library(
        dns-tools-commons
            src/commons/string_commons.cpp
    )

    target_include_directories(
        dns-tools-commons
            PUBLIC
                include
    )

# DNS library
    add_library(
        dns-tools-dns
            src/dns/rr.cpp
            src/dns/wire_format.cpp
            src/dns/zone_parser.cpp
            src/dns/rrset.cpp
            src/dns/nsec.cpp
            src/dns/zone_writer.cpp
    )

    target_include_directories(
        dns-tools-dns
            PUBLIC
                include
    )

    target_link_libraries(
        dns-tools-dns
            PRIVATE
                dns-tools-commons
    )

# Crypto library
    add_library(
        dns-tools-crypto
            src/crypto/digest.cpp
            src/crypto/sign.cpp
            src/crypto/verify.cpp
    )

    target_include_directories(
        dns-tools-crypto
            PUBLIC
                include
    )

    target_link_libraries(
        dns-tools-crypto
            PRIVATE
                OpenSSL::Crypto
                dns-tools-commons
                dns-tools-dns
    )

# Context library
    add_library(
        dns-tools-context
            src/context/context.cpp
    )

    target_include_directories(
        dns-tools-context
            PUBLIC
                include
    )

    target_link_libraries(
        dns-tools-context
            PRIVATE
                dns-tools-crypto
    )

# CLI library
    add_library(
        dns-tools-cli
            src/cli/sign_command.cpp
            src/cli/verify_command.cpp
            src/cli/digest_command.cpp
            src/context/context.cpp
            src/crypto/digest.cpp
            src/crypto/sign.cpp
            src/crypto/verify.cpp
    )

    target_include_directories(
        dns-tools-cli
            PUBLIC
                include
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
)

target_include_directories(
    dns-tools
    PUBLIC
        "${PROJECT_SOURCE_DIR}"
)

