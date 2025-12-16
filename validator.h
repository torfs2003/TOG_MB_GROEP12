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

enum AlertSeverity {
    SEV_CRITICAL_HARD_BLOCK,
    SEV_HIGH_RISK,
    SEV_MEDIUM_PRIVILEGE,
    SEV_LOW_SUSPICIOUS
};

struct ParserAction {
    enum Type { SHIFT, REDUCE, ACCEPT, ERROR } type;
    int state; 
    string lhs;   // Left-Hand Side
    int rhsSize;  // Aantal symbolen aan de rechterkant
    };

struct SecurityFinding {
    AlertSeverity severity;
    string message;
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
private:
    // De Matrix: Koppelt een Rol aan een Set van toegestane commando's
    unordered_map<UserRole, unordered_set<string>> permissions;
    void loadPermissions();

public:
    RBACManager();
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
private:
    vector<SecurityFinding> findings;
public:
    const vector<SecurityFinding>& getLastFindings() const { return findings; }
    bool isDangerous(SimpleLexer& lexer, string query, UserRole role);
};

// Hulpfuncties
void ensureParseTable(const string& grammarFile, const string& tableFile);
void runCheck(const string& tableFile, const vector<string>& queries, UserRole role);

#endif //TOG_VALIDATOR_H