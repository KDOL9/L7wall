cmake_minimum_required(VERSION 3.24)
project(l7wall VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(L7WALL_BUILD_TESTS "Build unit tests" ON)
option(L7WALL_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(L7WALL_WERROR "Treat warnings as errors" OFF)

add_library(l7wall_warnings INTERFACE)
target_compile_options(l7wall_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
    $<$<BOOL:${L7WALL_WERROR}>:-Werror>)

if(L7WALL_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
endif()

add_library(l7wall_core
    src/ip_address.cpp
    src/packet.cpp
    src/pcap_reader.cpp
    src/flow_table.cpp
    src/tcp_state.cpp
    src/tls.cpp)
target_include_directories(l7wall_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(l7wall_core PRIVATE l7wall_warnings)

add_executable(l7wall apps/l7wall_cli.cpp)
target_link_libraries(l7wall PRIVATE l7wall_core l7wall_warnings)

if(L7WALL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
