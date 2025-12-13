//
// Created by lasse on 12/12/2025.
//
#ifndef VALIDATOR_H
#define VALIDATOR_H

#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <stack>
#include "json.hpp" 

using json = nlohmann::json;
using namespace std;

struct Token {
    string type;  
    string value; 
};

struct ParserProduction {
    std::string head;
    std::vector<std::string> body;
    
    bool operator==(const ParserProduction& other) const {
        return head == other.head && body == other.body;
    }
};

struct ParserAction {
    enum Type { SHIFT, REDUCE, ACCEPT, ERROR } type;
    int state; 
    string lhs;  
    int rhsSize; 
};

class SimpleLexer {
    unordered_map<string, string> keywords;
    unordered_map<char, string> symbols;

public:
    SimpleLexer();                        
    vector<Token> tokenize(string input); 
};

class LALRParser {
    unordered_map<int, unordered_map<string, ParserAction>> actionTable;
    unordered_map<int, unordered_map<string, int>> gotoTable;

public:
    LALRParser(string filename);     
    bool parse(vector<Token>& tokens);    
};
void printErrors(SimpleLexer& lexer, LALRParser& parser, const vector<string>& queries);

#endif