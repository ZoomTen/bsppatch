
add_library(libbsp STATIC
    interpreter.c
    vm_object.c
    ../../include/bsp.h

    sha1/sha1.c
    sha1/sha1.h
)

target_include_directories(libbsp PUBLIC
    ../../include 
)