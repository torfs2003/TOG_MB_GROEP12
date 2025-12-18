#ifndef LEXER_H
#define LEXER_H

#include "common.h"
#include "../core/Token.h"

// Eenvoudige lexer die een SQL string omzet in tokens.
class SimpleLexer {
    std::unordered_map<std::string, std::string> keywords;
    std::unordered_map<char, std::string> symbols;
public:
    SimpleLexer();
    std::vector<Token> tokenize(std::string input);
};



#endif //LEXER_H
