#ifndef LALRPARSER_H
#define LALRPARSER_H

#include "common.h"
#include "../core/Token.h"

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
    bool parse(std::vector<Token>& tokens);
};



#endif //LALRPARSER_H
