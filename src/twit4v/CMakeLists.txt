file(GLOB_RECURSE Twit4v_SOURCES "*.cpp")
file(GLOB_RECURSE Twit4v_HEADERS "${PROJECT_SOURCE_DIR}/twit4v/*.hpp")

add_library(${Twit4v_LIBRARY_NAME} ${Twit4v_SOURCES} ${Twit4v_HEADERS})
qt5_use_modules(${Twit4v_LIBRARY_NAME} ${Twit4v_QT_MODULES})
