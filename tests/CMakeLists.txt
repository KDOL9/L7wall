include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(l7wall_tests
    ip_address_test.cpp
    packet_test.cpp)
target_link_libraries(l7wall_tests PRIVATE l7wall_core l7wall_warnings GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(l7wall_tests)
