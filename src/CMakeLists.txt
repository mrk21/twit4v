file(GLOB Twit4v_MAIN_SOURCES "*.cpp")

foreach(_path ${Twit4v_MAIN_SOURCES})
  get_filename_component(_name ${_path} NAME_WE)
  set(_bin_name "${_name}_bin")
  add_executable(${_bin_name} ${_path})
  target_link_libraries(${_bin_name} ${Twit4v_LIBRARY_NAME})
endforeach()
