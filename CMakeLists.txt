cmake_minimum_required(VERSION 3.28)
project(SQLGuard)

set(CMAKE_CXX_STANDARD 20)

add_executable(SQLGuard 
        main.cpp
        LALR.cpp
        LALR.h
        json.hpp
        common.h
        lexer/Lexer.cpp
        lexer/Lexer.h
        core/Token.h
        lexer/Keywords.h
        parser/LALRParser.cpp
        parser/LALRParser.h
        security/SecurityAnalyzer.cpp
        security/SecurityAnalyzer.h
        security/SecurityTypes.h
        auth/UserRole.h
        auth/RBACManager.cpp
        auth/RBACManager.h
        utils/QueryRunner.cpp
        utils/QueryRunner.h
)

target_include_directories(SQLGuard PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(SQLGuard PRIVATE 
    PROJECT_ROOT="${CMAKE_CURRENT_SOURCE_DIR}"
)