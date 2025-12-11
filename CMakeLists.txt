cmake_minimum_required(VERSION 3.28)
project(SQLGuard)

set(CMAKE_CXX_STANDARD 20)

add_executable(SQLGuard main.cpp
        CFG.h
        CFG.cpp
        json.hpp)

add_custom_target(copy_query_file ALL
        COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_SOURCE_DIR}/DQL.json ${CMAKE_BINARY_DIR}/DQL.json
)

add_dependencies(SQLGuard copy_query_file)