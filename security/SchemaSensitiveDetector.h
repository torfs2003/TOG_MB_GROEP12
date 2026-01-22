//
// Created by Seher Goker on 15/01/2026.
//
#include <vector>
#include <iostream>
#include "../core/AST.h"
using namespace std;
#ifndef LALR_1__PARSER_SCHEMASENSITIVEDETECTOR_H
#define LALR_1__PARSER_SCHEMASENSITIVEDETECTOR_H


class SchemaSensitiveDetector {

public:
    explicit SchemaSensitiveDetector(ASTNode* ast);

    void recursive(ASTNode* parent);



private:
    vector<string> warning = { "information_schema","INFORMATION_SCHEMA", "sys", "pg_catalog", "mysql", "performance_schema", "sqlite_master", "DATABASE"};
    bool schema_sniffing = false;
};


#endif //LALR_1__PARSER_SCHEMASENSITIVEDETECTOR_H
