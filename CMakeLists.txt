cmake_minimum_required(VERSION 3.13...3.27)

project(bsppatch
    VERSION 0.1
    DESCRIPTION "A BSP patcher"
    LANGUAGES C
)

set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

add_compile_options(-Wall -Wextra -pedantic)
add_compile_options(-fstrict-aliasing -Wstrict-aliasing)
add_compile_options(-Wswitch-enum -Wimplicit-fallthrough)
add_compile_options(-Wconversion)

add_subdirectory(src)