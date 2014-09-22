cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
project(Twit4v)

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  if(CMAKE_CXX_COMPILER_VERSION LESS "3.4")
    message(FATAL_ERROR "A supported Clang version is equal to or greater than 3.4!")
  endif()
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
  if(CMAKE_CXX_COMPILER_VERSION LESS "5.1")
    message(FATAL_ERROR "A supported AppleClang version is equal to or greater than 5.1!")
  endif()
else()
  message(FATAL_ERROR "Supported compilers are Clang and AppleClang!")
endif()

find_package(Boost 1.55 REQUIRED)
find_package(Qt5Widgets 5.3 REQUIRED)
message(STATUS "Qt Widgets version: ${Qt5Widgets_VERSION_STRING}")
find_package(OpenSSL REQUIRED)

set(CMAKE_CXX_FLAGS "-std=gnu++1y -stdlib=libc++ -Wall -Wextra -Wno-unused-parameter")
set(Twit4v_LIBRARY_NAME twit4v)

include_directories(
  ${PROJECT_SOURCE_DIR}
  ${Qt5Widgets_INCLUDE_DIRS}
  ${PROJECT_SOURCE_DIR}/vendor/cpp-netlib
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
