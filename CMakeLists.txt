cmake_minimum_required(VERSION 3.22)
project(kprobes C)

set(CMAKE_C_STANDARD 90)

# Module info
add_definitions(-D__KERNEL__ -DMODULE)

# Find the kernel release
execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Find the headers
find_path(
        KERNEL_HEADERS_DIR
        include/linux/user.h
        PATHS /lib/modules/${KERNEL_RELEASE}/build
)

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers: ${KERNEL_HEADERS_DIR}")

# Add header files
include_directories(
        ${KERNEL_HEADERS_DIR}/include
        ${KERNEL_HEADERS_DIR}/arch/x86/include
        ${KERNEL_HEADERS_DIR}/arch/x86/include/generated
)

set(DRIVER_FILE hello.ko)
set(KBUILD_CMD $(MAKE) -C ${KERNEL_HEADERS_DIR} modules M=${CMAKE_CURRENT_BINARY_DIR} src=${CMAKE_CURRENT_SOURCE_DIR})

# Generate the Kbuild file through cmake.
FILE(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild "obj-m := hello.o")

add_custom_command(OUTPUT ${DRIVER_FILE}
        COMMAND ${KBUILD_CMD}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS hello.c VERBATIM)

add_custom_target(driver ALL DEPENDS ${DRIVER_FILE})
# Parse c files
add_library(dummy_target hello.c)
