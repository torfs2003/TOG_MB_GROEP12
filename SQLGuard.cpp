#include "SQLGuard.h"

SQLGuard::SQLGuard() {
    tablesLoaded = false;
}

string tokenToString(TokenType t) {}

ParseNode::ParseNode(string v, TokenType t, bool taint) 
    : value(v), type(t), isTainted(taint) {}

void SQLGuard::analyze(string query) {}


vector<Token> SQLGuard::Lexer(string query) {
}

void SQLGuard::debugLexer(string query) {}

bool tablesLoaded = false;

// --- STEP 1: DEFINE YOUR TABLE DIMENSIONS HERE ---
const int NUM_STATES = 0;   
const int NUM_TERMINALS = 0; 
const int NUM_NONTERMINALS = 0;

void SQLGuard::initParserTables() {
    if (tablesLoaded) return;

    // Resize tables to fit the real data
    actionTable.resize(NUM_STATES, vector<TableEntry>(NUM_TERMINALS, {ACT_ERROR, 0}));
    gotoTable.resize(NUM_STATES, vector<TableEntry>(NUM_NONTERMINALS, {ACT_ERROR, 0}));
    grammarRules.resize(100); 


    tablesLoaded = true;
}


// --- STEP 2: MAP TOKENS TO COLUMNS ---
// The table will have columns

int mapTokenToColumn(TokenType t) {
}

ParseNode* SQLGuard::parse(vector<Token>& tokens) {}

bool SQLGuard::scanTree(ParseNode* node) {}