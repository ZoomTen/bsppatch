add_subdirectory(bsp)

add_executable(bsppatch
    bsppatch.c
    ../include/bsp.h
)

target_link_libraries(bsppatch PUBLIC
    libbsp
)