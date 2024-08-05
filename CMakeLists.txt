cmake_minimum_required(VERSION 3.8)
add_library(LZO_LIB STATIC ./lzo-2.10/include/lzo/lzo1z.h ./lzo-2.10/src/lzo_init.c ./lzo-2.10/src/lzo1z_9x.c)
add_executable(packer packer.cpp)
target_link_libraries(packer LZO_LIB)





