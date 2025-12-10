#ifndef SQLGUARD_H
#define SQLGUARD_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <cctype>
#include <stack>

using namespace std;

enum TokenType {
    T_EOF = 0, T_ERROR,

    // Punctuation & Delimiters
    T_PCOMMA,       // ;
    T_COMMA,        // ,
    T_LPAREN,       // (
    T_RPAREN,       // )
    T_DOT,          // .
    T_UNDERSCORE,   // _

    // Operators (Math & Logic)
    T_ADD, T_MINUS, T_STAR, T_DIVIDE, T_PERCENT, // + - * / %
    T_EQ, T_NEQ, T_LT, T_GT, T_LTE, T_GTE,       // = != < > <= >=
    T_AMP, T_PIPE, T_CARET, T_CONCAT_OP,         // & | ^ ||

    // Keywords: Logic
    T_AND, T_OR, T_NOT, T_IS, T_NULL, 
    T_BETWEEN, T_IN, T_EXISTS, T_LIKE, 
    T_ALL, T_ANY, T_SOME,

    // Keywords: Select & Clauses
    T_SELECT, T_FROM, T_WHERE, T_GROUP, T_HAVING, T_ORDER, T_BY, 
    T_TOP, T_DISTINCT, T_INTO, T_AS,
    T_UNION, T_UNIONALL, T_INTERSECT, T_EXCEPT,

    // Keywords: Joins
    T_JOIN, T_LJOIN, T_RJOIN, T_FJOIN, T_INNER, T_NATURAL, T_CROSS, 
    T_ON, T_USING,

    // Keywords: Modification (DML)
    T_INSERT, T_VALUES, T_UPDATE, T_SET, T_DELETE, T_TRUNCATE,

    // Keywords: DDL & definitions
    T_CREATE, T_DATABASE, T_TABLE, T_INDEX, T_VIEW, T_PROCEDURE,
    T_DROP, T_ALTER, T_COLUMN, T_CONSTRAINT, T_BACKUP,
    T_PK, T_FK, T_REFERENCES, T_AUTOINCREMENT, T_UNIQUE, T_CHECK, T_DEFAULT,

    // Keywords: Functions & Window
    T_COUNT, T_SUM, T_AVG, T_MIN, T_MAX,
    T_OVER, T_PARTITION, T_ROW_NUMBER, T_RANK,
    T_CAST, T_CONVERT, 
    T_CASE, T_END, T_WHEN, T_THEN, T_ELSE,
    T_ASC, T_DESC, T_WITH,

    // Data Types
    T_INT_TYPE, T_INTEGER, T_TINYINT, T_BIGINT,
    T_FLOAT_TYPE, T_REAL, T_DECIMAL, T_NUMERIC,
    T_VARCHAR, T_CHAR, T_TEXT, T_STRING_TYPE,
    T_DATE, T_DATETIME, T_TIMESTAMP, T_TIME, T_YEAR,
    T_BOOLEAN_TYPE, T_BIT, T_BLOB, T_JSON, T_XML,

    // Literals
    T_ID,           // Identifiers (table names, col names)
    T_INT,          // 123
    T_FLOAT,        // 12.34
    T_STRING,       // 'hello'
    T_BOOLEAN,      // TRUE/FALSE
    T_DATE_LIT,     // '2023-01-01'
    
    // Lexer internal (optional, not in CFG but needed for skipping)
    T_COMMENT 
};

enum ActionType { ACT_SHIFT, ACT_REDUCE, ACT_ACCEPT, ACT_ERROR, ACT_GOTO };

struct TableEntry {
    ActionType type;
    int value;
};


struct GrammarRule {
    int lhsID;      
    int rhsLength;
};

struct Token {
    TokenType type;
    string value;
    int line;
    int column;
};

struct ParseNode {
    string value;
    TokenType type;
    bool isTainted;
    vector<ParseNode*> children;
    ParseNode(string v, TokenType t, bool taint=false);
};

class SQLGuard {
public:
    SQLGuard();
    void analyze(string query);
    void debugLexer(string query);

private:
    vector<Token> Lexer(string query);    
    ParseNode* parse(vector<Token>& tokens);
    bool scanTree(ParseNode* node);
    vector<vector<TableEntry>> actionTable;
    vector<vector<TableEntry>> gotoTable;
    vector<GrammarRule> grammarRules;
    bool tablesLoaded;
    void initParserTables();
    int mapTokenToColumn(TokenType t);
};

#endif