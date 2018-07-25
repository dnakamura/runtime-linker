
add_library(objectlib OBJECT Object.c)

file(GENERATE
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/objectdir.cpp
    INPUT ${CMAKE_CURRENT_SOURCE_DIR}/objectdir.cpp.in 
)

add_executable(testexe
    main.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/objectdir.cpp
)
target_link_libraries(testexe PRIVATE objload)
target_include_directories(testexe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
