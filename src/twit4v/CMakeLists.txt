file(GLOB_RECURSE Twit4v_SOURCES "*.cpp")
file(GLOB_RECURSE Twit4v_HEADERS "${PROJECT_SOURCE_DIR}/twit4v/*.hpp")
file(GLOB_RECURSE Twit4v_UI_SOURCES "*.ui")
qt5_wrap_ui(Twit4v_UI_HEADERS ${Twit4v_UI_SOURCES})

add_library(${Twit4v_LIBRARY_NAME} ${Twit4v_SOURCES} ${Twit4v_HEADERS} ${Twit4v_UI_HEADERS})
qt5_use_modules(${Twit4v_LIBRARY_NAME} ${Twit4v_QT_MODULES})
