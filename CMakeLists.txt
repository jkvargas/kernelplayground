cmake_minimum_required(VERSION 3.22)
project(ebpf C)

file(GLOB SOURCE src/*.c)
file(GLOB HEADERS include/*.h)

include_directories(include)

add_library(${PROJECT_NAME} ${SOURCE} ${HEADERS})