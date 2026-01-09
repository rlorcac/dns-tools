cmake_minimum_required(VERSION 3.10)

# set the project name
project(dns-tools)

# add the executable
add_executable(dns-tools src/main.cpp)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

target_include_directories(dns-tools PUBLIC
                          "${PROJECT_SOURCE_DIR}/include"
                          )