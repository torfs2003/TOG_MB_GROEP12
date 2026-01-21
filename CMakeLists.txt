cmake_minimum_required(VERSION 3.26)
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
        security/TaintAnalyzer.cpp
        security/TaintAnalyzer.h
        auth/UserRole.h
        auth/RBACManager.cpp
        auth/RBACManager.h
        utils/QueryRunner.cpp
        utils/QueryRunner.h
        core/AST.h
        auth/User.cpp
        auth/User.h
        utils/AuditLogger.cpp
        utils/AuditLogger.h


)
target_include_directories(SQLGuard PRIVATE ${CMAKE_SOURCE_DIR})

add_custom_target(copy_resources ALL
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/CFG.json ${CMAKE_BINARY_DIR}/CFG.json
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/user.json ${CMAKE_BINARY_DIR}/user.json
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_SOURCE_DIR}/query.json ${CMAKE_BINARY_DIR}/query.json
)

add_dependencies(SQLGuard copy_resources)