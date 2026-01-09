cmake_minimum_required(VERSION 3.10)

project(
    dns-tools
    VERSION 0.1
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(CLI11 REQUIRED)

add_library(
    dns-tools-cli
        src/cli/sign/sign_command.cpp
        src/cli/verify/verify_command.cpp
)

target_include_directories(
    dns-tools-cli
        PUBLIC
            src/cli/sign
            src/cli/verify
)

target_link_libraries(
    dns-tools-cli
    PRIVATE
        CLI11::CLI11
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
