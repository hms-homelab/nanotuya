cmake_minimum_required(VERSION 3.16)

# Read version from VERSION file
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" NANOTUYA_VERSION)
string(STRIP "${NANOTUYA_VERSION}" NANOTUYA_VERSION)

project(nanotuya VERSION ${NANOTUYA_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2 -pthread")
endif()

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

# Library target
add_library(nanotuya
    src/TuyaProtocol.cpp
    src/TuyaDevice.cpp
)
target_include_directories(nanotuya PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    ${JSONCPP_INCLUDE_DIRS}
)
target_link_libraries(nanotuya PUBLIC OpenSSL::Crypto ${JSONCPP_LIBRARIES})

# Install
install(TARGETS nanotuya DESTINATION lib)
install(DIRECTORY include/nanotuya DESTINATION include)

# Examples
option(BUILD_EXAMPLES "Build examples" OFF)
if(BUILD_EXAMPLES)
    add_executable(query_device examples/query_device.cpp)
    target_link_libraries(query_device nanotuya)
endif()

# Tests
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    find_package(GTest REQUIRED)
    enable_testing()
    add_executable(run_tests
        tests/test_tuya_protocol.cpp
        tests/test_tuya_device.cpp
    )
    target_link_libraries(run_tests nanotuya GTest::gtest GTest::gtest_main)
    add_test(NAME unit_tests COMMAND run_tests)
endif()
