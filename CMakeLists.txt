cmake_minimum_required(VERSION 3.2 FATAL_ERROR)

project(objload VERSION 1.0.0 LANGUAGES CXX C)
set(CMAKE_CXX_STANDARD 17)

add_library(objload STATIC
    ObjLoad.cpp
)
target_include_directories(objload PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(objload PRIVATE dl)


file(GENERATE 
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/objectdir.cpp 
    INPUT ${CMAKE_CURRENT_SOURCE_DIR}/objectdir.cpp.in
)

add_executable(testexe
    main.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/objectdir.cpp
)
target_link_libraries(testexe PRIVATE objload)


add_library(objectlib OBJECT Object.c)
