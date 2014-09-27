set(CMAKE_AUTOMOC ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

file(GLOB_RECURSE Twit4v_SOURCES "*.cpp")
file(GLOB_RECURSE Twit4v_HEADERS "${PROJECT_SOURCE_DIR}/twit4v/*.hpp")
file(GLOB_RECURSE Twit4v_UI_SOURCES "*.ui")
qt5_wrap_ui(Twit4v_UI_HEADERS ${Twit4v_UI_SOURCES})

add_library(${Twit4v_LIBRARY_NAME}
  ${Twit4v_SOURCES}
  ${Twit4v_HEADERS}
  ${Twit4v_UI_HEADERS}
)
target_link_libraries(${Twit4v_LIBRARY_NAME}
  ${Boost_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  cppnetlib-uri
  cppnetlib-client-connections
)
qt5_use_modules(${Twit4v_LIBRARY_NAME}
  Widgets
)
