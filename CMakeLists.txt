cmake_minimum_required(VERSION 3.7)
project(qasm VERSION 1.0)

set(SOURCES
    src/main.c
    src/gen.c
)
include_directories(${CMAKE_SOURCE_DIR}/include)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -Wall")

add_executable(qasm ${SOURCES})
