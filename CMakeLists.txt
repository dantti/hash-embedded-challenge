cmake_minimum_required(VERSION 3.14)

project(hash-embedded LANGUAGES C)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_library(hash_embedded SHARED ber-tlv.c ber-tlv.h)

add_executable(hash-embedded
  main.c
)
target_link_libraries(hash-embedded hash_embedded)
