cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

project(runtime-linker VERSION 1.0.0 LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 17)

# Do some basic sanity checks
include(CheckIncludeFile)
check_include_file(elf.h HAS_ELF_H)
if(NOT HAS_ELF_H)
    message(FATAL_ERROR "runtime-linker requires elf.h")
endif()

find_package(Boost REQUIRED COMPONENTS log)

add_library(objload STATIC
    source/ObjLoad.cpp
)
target_include_directories(objload PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(objload PRIVATE dl)

add_subdirectory(test)
