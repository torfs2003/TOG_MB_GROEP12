#include "validator.h" 
#include <iostream>
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <iomanip>

using namespace std;

SimpleLexer::SimpleLexer() {
    keywords["ADD"] = "T_ADD"; 
    keywords["ALL"] = "T_ALL";
    keywords["ALTER"] = "T_ALTER";
    keywords["AND"] = "T_AND";
    keywords["ANY"] = "T_ANY";
    keywords["AS"] = "T_AS";
    keywords["ASC"] = "T_ASC";
    keywords["AVG"] = "T_AVG";
    keywords["BACKUP"] = "T_BACKUP";
    keywords["BETWEEN"] = "T_BETWEEN";
    keywords["BIGINT"] = "T_BIGINT";
    keywords["BIT"] = "T_BIT";
    keywords["BLOB"] = "T_BLOB";
    keywords["BOOLEAN"] = "T_BOOLEAN_TYPE";
    keywords["BY"] = "T_BY";
    keywords["CASE"] = "T_CASE";
    keywords["CAST"] = "T_CAST";
    keywords["CHAR"] = "T_CHAR";
    keywords["CHECK"] = "T_CHECK";
    keywords["COLUMN"] = "T_COLUMN";
    keywords["CONSTRAINT"] = "T_CONSTRAINT";
    keywords["CONVERT"] = "T_CONVERT";
    keywords["COUNT"] = "T_COUNT";
    keywords["CREATE"] = "T_CREATE";
    keywords["CROSS"] = "T_CROSS";
    keywords["DATABASE"] = "T_DATABASE";
    keywords["DATE"] = "T_DATE";
    keywords["DATETIME"] = "T_DATETIME";
    keywords["DECIMAL"] = "T_DECIMAL";
    keywords["DEFAULT"] = "T_DEFAULT";
    keywords["DELETE"] = "T_DELETE";
    keywords["CASCADE"]  = "T_CASCADE";
    keywords["RESTRICT"] = "T_RESTRICT";
    keywords["ACTION"]   = "T_ACTION";
    keywords["NO"]       = "T_NO";
    keywords["DESC"] = "T_DESC";
    keywords["DISTINCT"] = "T_DISTINCT";
    keywords["DROP"] = "T_DROP";
    keywords["ELSE"] = "T_ELSE";
    keywords["BEGIN"] = "T_BEGIN";
    keywords["END"] = "T_END";
    keywords["EXCEPT"] = "T_EXCEPT";
    keywords["EXISTS"] = "T_EXISTS";
    keywords["FALSE"] = "T_BOOLEAN";
    keywords["FLOAT"] = "T_FLOAT_TYPE";
    keywords["FROM"] = "T_FROM";
    keywords["FULL"] = "T_FJOIN"; 
    keywords["GROUP"] = "T_GROUP";
    keywords["HAVING"] = "T_HAVING";
    keywords["IN"] = "T_IN";
    keywords["INDEX"] = "T_INDEX";
    keywords["INNER"] = "T_INNER";
    keywords["INSERT"] = "T_INSERT";
    keywords["INT"] = "T_INT_TYPE";
    keywords["INTEGER"] = "T_INTEGER";
    keywords["INTERSECT"] = "T_INTERSECT";
    keywords["INTO"] = "T_INTO";
    keywords["IS"] = "T_IS";
    keywords["JOIN"] = "T_JOIN";
    keywords["JSON"] = "T_JSON";
    keywords["LEFT"] = "T_LJOIN"; 
    keywords["LIKE"] = "T_LIKE";
    keywords["MAX"] = "T_MAX";
    keywords["MIN"] = "T_MIN";
    keywords["NATURAL"] = "T_NATURAL";
    keywords["NOT"] = "T_NOT";
    keywords["NULL"] = "T_NULL";
    keywords["UNBOUNDED"] = "T_UNBOUNDED";
    keywords["NUMERIC"] = "T_NUMERIC";
    keywords["ON"] = "T_ON";
    keywords["OR"] = "T_OR";
    keywords["ORDER"] = "T_ORDER";
    keywords["OVER"] = "T_OVER";
    keywords["PARTITION"] = "T_PARTITION";
    keywords["PERCENT"] = "T_PERCENT"; 
    keywords["PROCEDURE"] = "T_PROCEDURE";
    keywords["RANK"] = "T_RANK";
    keywords["REAL"] = "T_REAL";
    keywords["REFERENCES"] = "T_REFERENCES";
    keywords["RIGHT"] = "T_RJOIN";
    keywords["ROW"] = "T_ROW"; 
    keywords["ROWS"] = "T_ROWS";
    keywords["RANGE"] = "T_RANGE";
    keywords["ROW_NUMBER"] = "T_ROW_NUMBER";
    keywords["SELECT"] = "T_SELECT";
    keywords["SET"] = "T_SET";
    keywords["SOME"] = "T_SOME";
    keywords["STRING"] = "T_STRING_TYPE";
    keywords["SUM"] = "T_SUM";
    keywords["TABLE"] = "T_TABLE";
    keywords["TEXT"] = "T_TEXT";
    keywords["THEN"] = "T_THEN";
    keywords["TIME"] = "T_TIME";
    keywords["TIMESTAMP"] = "T_TIMESTAMP";
    keywords["TINYINT"] = "T_TINYINT";
    keywords["TOP"] = "T_TOP";
    keywords["TRUNCATE"] = "T_TRUNCATE";
    keywords["TRUE"] = "T_BOOLEAN"; 
    keywords["UNION"] = "T_UNION";
    keywords["UNIQUE"] = "T_UNIQUE";
    keywords["UPDATE"] = "T_UPDATE";
    keywords["USING"] = "T_USING";
    keywords["VALUES"] = "T_VALUES";
    keywords["VARCHAR"] = "T_VARCHAR";
    keywords["VIEW"] = "T_VIEW";
    keywords["WHEN"] = "T_WHEN";
    keywords["WHERE"] = "T_WHERE";
    keywords["WITH"] = "T_WITH";
    keywords["XML"] = "T_XML";
    keywords["YEAR"] = "T_YEAR";
    keywords["AUTOINCREMENT"] = "T_AUTOINCREMENT";
    keywords["CURRENT_TIMESTAMP"] = "T_DEFAULT"; 
    keywords["CURRENT"] = "T_CURRENT";
    keywords["FOLLOWING"] = "T_FOLLOWING";
    keywords["PRECEDING"] = "T_PRECEDING";
    keywords["OUTER"] = "T_OUTER";
    keywords["IF"] = "T_IF";
    symbols['*'] = "T_STAR";    symbols[','] = "T_COMMA";
    symbols[';'] = "T_PCOMMA";     symbols['('] = "T_LPAREN";
    symbols[')'] = "T_RPAREN";  symbols['='] = "T_EQ";
    symbols['+'] = "T_ADD";     symbols['.'] = "T_DOT";
    symbols['>'] = "T_GT";      symbols['<'] = "T_LT";
    symbols['-'] = "T_MINUS";   symbols['/'] = "T_DIVIDE";
    symbols['%'] = "T_PERCENT"; symbols['^'] = "T_CARET";
    symbols['&'] = "T_AMP";     symbols['|'] = "T_PIPE";
}

vector<Token> SimpleLexer::tokenize(string input) {
    vector<Token> tokens;
    int i = 0;
    while (i < input.length()) {
        char c = input[i];

        // 1. Skip Whitespace
        if (isspace(c)) {
            i++;
            continue;
        }

        // ==========================================
        // FIX 1: HEXADECIMAL SUPPORT (For Query 1)
        // ==========================================
        if (c == '0' && i + 1 < input.length() && (input[i+1] == 'x' || input[i+1] == 'X')) {
            string hexStr = "0x";
            i += 2; // Skip '0x'
            while (i < input.length() && isxdigit(input[i])) {
                hexStr += input[i++];
            }
            tokens.push_back({"T_INT", hexStr}); // Treat Hex as INT
            continue;
        }

        // 2. Standard Numbers
        if (isdigit(c)) {
            string num;
            bool isFloat = false;
            while (i < input.length() && (isdigit(input[i]) || input[i] == '.')) {
                if (input[i] == '.') isFloat = true;
                num += input[i++];
            }
            tokens.push_back({isFloat ? "T_FLOAT" : "T_INT", num});
            continue;
        }

        // 3. Keywords & Identifiers (with PRIMARY/FOREIGN KEY Lookahead)
        if (isalpha(c) || c == '_') {
            string word;
            while (i < input.length() && (isalnum(input[i]) || input[i] == '_')) {
                word += input[i++];
            }
            
            string upper = word;
            transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

            // --- HANDLING COMPOSITE TOKENS (PRIMARY KEY / FOREIGN KEY) ---
            if (upper == "PRIMARY" || upper == "FOREIGN") {
                int tempI = i; 
                // Peek forward past whitespace
                while (tempI < input.length() && isspace(input[tempI])) tempI++;

                // Read next word
                if (tempI < input.length() && (isalpha(input[tempI]) || input[tempI] == '_')) {
                    string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    string nextUpper = nextWord;
                    transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

                    // If we found "KEY", merge them into one token
                    if (nextUpper == "KEY") {
                        i = tempI; // Advance real cursor
                        if (upper == "PRIMARY") {
                            tokens.push_back({"T_PK", "PRIMARY KEY"});
                        } else {
                            tokens.push_back({"T_FK", "FOREIGN KEY"});
                        }
                        continue; // Successfully handled composite token
                    }
                }
            }

            // Standard Map Lookup
            if (keywords.count(upper)) {
                tokens.push_back({keywords[upper], word});
            } else {
                tokens.push_back({"T_ID", word});
            }
            continue;
        }

        // ==========================================
        // FIX 2: ESCAPED STRING SUPPORT (For Query 10)
        // ==========================================
        if (c == '\'') {
            string s;
            i++; // Skip opening quote
            while (i < input.length()) {
                // Check for escaped quote: ''
                if (input[i] == '\'' && i + 1 < input.length() && input[i+1] == '\'') {
                    s += "'";  // Add actual single quote
                    i += 2;    // Skip both quote chars
                } 
                // Check for closing quote
                else if (input[i] == '\'') {
                    i++; // Skip closing quote
                    break;
                } 
                // Normal character
                else {
                    s += input[i++];
                }
            }
            tokens.push_back({"T_STRING", s});
            continue;
        }

        // 5. Symbols
        if (symbols.count(c) || c == '!' || c == '<' || c == '>' || c == '|') {
            string op(1, c);
            bool handled = false;

            if (i + 1 < input.length()) {
                char next = input[i+1];
                if (c == '>' && next == '=') { 
                    tokens.push_back({"T_GTE", ">="}); i += 2; handled = true; 
                }
                else if (c == '<' && next == '=') { 
                    tokens.push_back({"T_LTE", "<="}); i += 2; handled = true; 
                }
                else if (c == '<' && next == '>') { 
                    tokens.push_back({"T_NEQ", "<>"}); i += 2; handled = true; 
                }
                else if (c == '!' && next == '=') { 
                    tokens.push_back({"T_NEQ", "!="}); i += 2; handled = true; 
                }
                else if (c == '|' && next == '|') { 
                    tokens.push_back({"T_CONCAT_OP", "||"}); i += 2; handled = true; 
                }
            }

            if (handled) continue;

            if (symbols.count(c)) {
                tokens.push_back({symbols[c], op});
                i++;
                continue;
            }
        }

        i++; 
    }
    tokens.push_back({"T_EOF", ""});

    tokens.push_back({"$", ""}); 
    return tokens;
}


LALRParser::LALRParser(string filename) {
    ifstream f(filename);
    if (!f.is_open()) {
        cerr << "Error: Could not open " << filename << endl;
        exit(1);
    }
    json j;
    f >> j;

    // Load Action Table
    for (auto& [stateStr, actions] : j["action_table"].items()) {
        int state = stoi(stateStr);
        for (auto& [sym, act] : actions.items()) {
            string type = act["type"];
            
            if (type == "SHIFT") {
                actionTable[state][sym] = {ParserAction::SHIFT, (int)act["state"], "", 0};
            } else if (type == "REDUCE") {
                actionTable[state][sym] = {ParserAction::REDUCE, 0, act["lhs"], (int)act["rhs"].size()};
            } else if (type == "ACCEPT") {
                actionTable[state][sym] = {ParserAction::ACCEPT, 0, "", 0};
            }
        }
    }

    // Load Goto Table
    for (auto& [stateStr, gotos] : j["goto_table"].items()) {
        int state = stoi(stateStr);
        for (auto& [nonTerm, nextState] : gotos.items()) {
            gotoTable[state][nonTerm] = (int)nextState;
        }
    }
}


bool LALRParser::parse(vector<Token>& tokens) {
    stack<int> stateStack;
    stateStack.push(0);

    int tokenIdx = 0;
    bool globalError = false;
    bool currentQueryError = false;
    bool recoveryMode = false;
    int queryCount = 1;

    cout << "Query " << setw(2) << queryCount << ": ";

    while (tokenIdx < tokens.size()) {
        int currentState = stateStack.top();
        Token currentToken = tokens[tokenIdx];
        string sym = currentToken.type;

        if (actionTable[currentState].find(sym) == actionTable[currentState].end()) {
            
            if (currentState == 0 && (sym == "T_EOF" || sym == "$")) {
                return !globalError; 
            }
            if (!recoveryMode) {
                cout << "\n    --> [Syntax Error] Unexpected '" << currentToken.value 
                     << "' (" << sym << ") in State " << currentState << endl;
                
                currentQueryError = true;
                globalError = true;
                recoveryMode = true; 
            }

            if (sym == "T_PCOMMA") {
                cout << "    --> [Recovery] Found delimiter ';'. Resuming parse..." << endl;
                
                cout << "\n         Result: \033[1;31m[REJECTED]\033[0m" << endl;

                while(!stateStack.empty()) stateStack.pop();
                stateStack.push(0);
                
                tokenIdx++; 
                recoveryMode = false;
                currentQueryError = false;
                queryCount++;

                if (tokenIdx < tokens.size() && tokens[tokenIdx].type != "T_EOF" && tokens[tokenIdx].type != "$") {
                    cout << "\nQuery " << setw(2) << queryCount << ": ";
                }
                continue;
            } 
            else if (sym == "T_EOF" || sym == "$") {
                 cout << "    --> [Recovery] Reached EOF. Stopping." << endl;
                 cout << "\n         Result: \033[1;31m[REJECTED]\033[0m" << endl;
                 return false; 
            }
            else {
                tokenIdx++; 
                continue;
            }
        }

       
        ParserAction act = actionTable[currentState][sym];

        if (act.type == ParserAction::SHIFT) {
            stateStack.push(act.state);
            tokenIdx++;

            if (sym == "T_PCOMMA") {
                if (!currentQueryError) {
                    cout << "\n         Result: \033[1;32m[ACCEPTED]\033[0m" << endl;
                } else {
                    cout << "\n         Result: \033[1;31m[REJECTED]\033[0m" << endl;
                }

                while(!stateStack.empty()) stateStack.pop();
                stateStack.push(0);
                
                recoveryMode = false;
                currentQueryError = false;
                queryCount++;

                if (tokenIdx < tokens.size() && tokens[tokenIdx].type != "T_EOF" && tokens[tokenIdx].type != "$") {
                    cout << "\nQuery " << setw(2) << queryCount << ": ";
                }
            }
        } 
        else if (act.type == ParserAction::REDUCE) {
            for (int i = 0; i < act.rhsSize; i++) {
                if (!stateStack.empty()) stateStack.pop();
            }
            if (stateStack.empty()) stateStack.push(0); 

            int topState = stateStack.top();
            if (gotoTable[topState].find(act.lhs) == gotoTable[topState].end()) {
                return false; 
            }
            stateStack.push(gotoTable[topState][act.lhs]);
        } 
        else if (act.type == ParserAction::ACCEPT) {
            if (!currentQueryError) cout << "\n         Result: \033[1;32m[ACCEPTED]\033[0m" << endl;
            else cout << "\n         Result: \033[1;31m[REJECTED]\033[0m" << endl;
            return !globalError;
        }
    }
    return !globalError;
}

void printErrors(SimpleLexer& lexer, LALRParser& parser, const vector<string>& queries) {
    string fullScript = "";
    for (const auto& q : queries) {
        fullScript += q + "\n";
    }
    cout << "Running parser on " << queries.size() << " queries...\n";
    cout << "---------------------------------------------------\n";

    vector<Token> tokens = lexer.tokenize(fullScript);

    bool result = parser.parse(tokens);

    cout << "---------------------------------------------------\n";
    cout << "Final Script Result: " << (result ? "SUCCESS" : "ERRORS DETECTED") << endl;
    cout << "================================\n";
    
}

