cmake_minimum_required(VERSION 3.22)
project(ebpf C)

set(CMAKE_C_COMPILER /usr/bin/clang)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(BpfObject REQUIRED)

file(GLOB APPS src/*.bpf.c)

foreach(APP ${APPS})
  get_filename_component(APP_STEM ${APP} NAME_WE)
  
  bpf_object(${APP_STEM} src/${APP_STEM}.bpf.c)
  add_dependencies(${APP_STEM}_skel libbpf-build)
  
  add_executable(${APP_STEM} src/${APP_STEM}.c)
  target_link_libraries(${APP_STEM} ${APP_STEM}_skel)
endforeach()
