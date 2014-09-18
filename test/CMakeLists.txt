find_package(Threads REQUIRED)

include_directories(${PROJECT_SOURCE_DIR}/test)
include_directories(${PROJECT_SOURCE_DIR}/vendor/bandit)
include_directories(${PROJECT_SOURCE_DIR}/vendor/bandit_with_gmock)
include_directories(${PROJECT_SOURCE_DIR}/vendor/gmock/include)
include_directories(${PROJECT_SOURCE_DIR}/vendor/gmock/gtest/include)

link_directories(${PROJECT_SOURCE_DIR}/vendor/gmock)
link_directories(${PROJECT_SOURCE_DIR}/vendor/gmock/gtest)

file(GLOB_RECURSE Twit4v_SPECS "spec/*_spec.cpp")
add_executable(spec_bin spec.cpp ${Twit4v_SPECS})
target_link_libraries(spec_bin ${Twit4v_LIBRARY_NAME} pthread gtest gmock)
