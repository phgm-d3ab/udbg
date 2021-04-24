cmake_minimum_required(VERSION 3.17)
project(udbg C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Wall -Wextra -O3")

add_library(udbg SHARED udbg.c)
target_link_libraries(${PROJECT_NAME} pthread)
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR})

if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_subdirectory(example)
endif ()
