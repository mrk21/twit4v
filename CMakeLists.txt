cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
project(Twit4v)

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  if(CMAKE_CXX_COMPILER_VERSION LESS "3.5")
    message(FATAL_ERROR "A supported Clang version is equal to or greater than 3.5!")
  endif()
else()
  message(FATAL_ERROR "Supported compiler is Clang!")
endif()

find_package(Boost 1.56 REQUIRED system thread)
find_package(OpenSSL 1.0.1 REQUIRED)
if(OPENSSL_VERSION MATCHES "[a-f]")
  message(FATAL_ERROR "This version contains a fatal bug by Heartbleed: ${OPENSSL_VERSION}")
endif()
find_package(Qt5Widgets 5.3 REQUIRED)
message(STATUS "Qt Widgets version: ${Qt5Widgets_VERSION_STRING}")

set(CMAKE_CXX_FLAGS "-std=gnu++14 -stdlib=libc++ -Wall -Wextra -Wno-unused-parameter")
set(Twit4v_LIBRARY_NAME twit4v)

include_directories(
  ${PROJECT_SOURCE_DIR}
  ${PROJECT_SOURCE_DIR}/vendor/cpp-netlib
  ${Boost_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
  ${Qt5Widgets_INCLUDE_DIRS}
)
link_directories(
  ${PROJECT_SOURCE_DIR}/vendor/gen/cpp-netlib/libs/network/src
)
add_definitions(
  -DBOOST_NETWORK_ENABLE_HTTPS
)

add_subdirectory(src/twit4v)

if(IS_TEST)
  add_subdirectory(test)
else()
  add_subdirectory(src)
endif()
