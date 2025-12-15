#ifndef VALIDATOR_H
#define VALIDATOR_H

#include "common.h"
#include "LALR.h"
#include <unordered_set>


enum UserRole {
    ROLE_CLIENT,    // R   (Read Only)
    ROLE_EMPLOYEE,  // RW  (Read + Write Data)
    ROLE_ADMIN      // RWX (Read + Write + Execute/DDL)
};

struct Token {
    string type;  
    string value; 
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

class RBACManager {
public:
    string getRoleName(UserRole role);
    bool hasPermission(UserRole role, const vector<Token>& tokens);
};

class LALRParser {
    unordered_map<int, unordered_map<string, ParserAction>> actionTable;
    unordered_map<int, unordered_map<string, int>> gotoTable;
public:
    LALRParser(string filename);     
    bool parse(vector<Token>& tokens);    
};

class SecurityAnalyzer {
public:
    const unordered_set<string> dangerous_keywords = {
        "T_DROP", "T_TRUNCATE", "T_ALTER", "T_PROCEDURE", "T_CREATE", "T_BACKUP"
    };
    const unordered_set<string> time_based_functions = {
        "SLEEP", "WAITFOR", "BENCHMARK"
    };

    bool isDangerous(SimpleLexer& lexer, string query, UserRole role);
};

void ensureParseTable(const string& grammarFile, const string& tableFile);
void runCheck(const string& tableFile, const vector<string>& queries, UserRole role);

#endif