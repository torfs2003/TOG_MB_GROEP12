#ifndef TOG_VALIDATOR_H
#define TOG_VALIDATOR_H

#include "common.h"
#include "LALR.h"


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
    string lhs;   // Left-Hand Side
    int rhsSize;  // Aantal symbolen aan de rechterkant
    };

// Eenvoudige lexer die een SQL string omzet in tokens.
class SimpleLexer {
    unordered_map<string, string> keywords;
    unordered_map<char, string> symbols;
public:
    SimpleLexer();                        
    vector<Token> tokenize(string input); 
};

// Controleert of een gebruiker (UserRole) een bepaald commando mag uitvoeren.
class RBACManager {
public:
    string getRoleName(UserRole role);
    bool hasPermission(UserRole role, const vector<Token>& tokens);
};

// De parser engine die de LALR(1) tabellen gebruikt om de syntax te valideren.
class LALRParser {
    unordered_map<int, unordered_map<string, ParserAction>> actionTable;
    unordered_map<int, unordered_map<string, int>> gotoTable;
public:
    LALRParser(string filename);     
    bool parse(vector<Token>& tokens);    
};

// Beveiligingslaag die zoekt naar SQL Injection patronen.
class SecurityAnalyzer {
public:
    // Keywords die duiden op destructieve acties
    const unordered_set<string> dangerous_keywords = {
        "T_DROP", "T_TRUNCATE", "T_ALTER", "T_PROCEDURE", "T_CREATE", "T_BACKUP"
    };
    // Functies die gebruikt worden voor Time-Based Blind SQL Injection
    const unordered_set<string> time_based_functions = {
        "SLEEP", "WAITFOR", "BENCHMARK"
    };

    bool isDangerous(SimpleLexer& lexer, string query, UserRole role);
};

// Hulpfuncties
void ensureParseTable(const string& grammarFile, const string& tableFile);
void runCheck(const string& tableFile, const vector<string>& queries, UserRole role);

#endif //TOG_VALIDATOR_H