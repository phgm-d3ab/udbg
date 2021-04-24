add_executable(example example.c)
target_link_libraries(example udbg)

#define some channels
add_compile_definitions(FOO=0x1)
add_compile_definitions(BAR=0x2)
add_compile_definitions(BAZ=0x4)

if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_definitions(UDBG)
endif ()
