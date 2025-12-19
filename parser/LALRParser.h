#ifndef LALRPARSER_H
#define LALRPARSER_H
#include <string>
#include <unordered_map>
#include <vector>
#include "../core/Token.h"
#include "../core/AST.h"

struct ParserAction {
    enum Type { SHIFT, REDUCE, ACCEPT, ERROR } type;
    int state;
    std::string lhs;   // Left-Hand Side
    int rhsSize;  // Aantal symbolen aan de rechterkant
};

// De parser engine die de LALR(1) tabellen gebruikt om de syntax te valideren.
class LALRParser {
    std::unordered_map<int, std::unordered_map<std::string, ParserAction>> actionTable;
    std::unordered_map<int, std::unordered_map<std::string, int>> gotoTable;
public:
    LALRParser(std::string filename);
    ASTNode* parse(const std::vector<Token>& tokens);
};



#endif //LALRPARSER_H
