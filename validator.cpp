#include "validator.h" 
#include <iostream>
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>

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
    keywords["FOREIGN"] = "T_FK";
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
    keywords["KEY"] = "T_PK"; 
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
    keywords["PRIMARY"] = "T_PK"; 
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
    symbols[';'] = "T_EOF";     symbols['('] = "T_LPAREN";
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

        if (isspace(c)) {
            i++;
            continue;
        }

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

        if (isalpha(c) || c == '_') {
            string word;
            while (i < input.length() && (isalnum(input[i]) || input[i] == '_')) {
                word += input[i++];
            }
            string upper = word;
            transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

            if (keywords.count(upper)) {
                tokens.push_back({keywords[upper], word});
            } else {
                tokens.push_back({"T_ID", word});
            }
            continue;
        }

        if (c == '\'') {
            string s;
            i++;
            while (i < input.length() && input[i] != '\'') {
                s += input[i++];
            }
            i++; 
            tokens.push_back({"T_STRING", s});
            continue;
        }

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
    
    while (true) {
        if (stateStack.empty()) return false;

        int currentState = stateStack.top();
        
        if (tokenIdx >= tokens.size()) return false; 
        
        Token currentToken = tokens[tokenIdx];
        string sym = currentToken.type;

        if (actionTable[currentState].find(sym) == actionTable[currentState].end()) {
            cerr << "  [Syntax Error] Unexpected token '" << currentToken.value 
                 << "' (" << sym << ") in State " << currentState << endl;
            return false;
        }

        ParserAction act = actionTable[currentState][sym];

        if (act.type == ParserAction::SHIFT) {
            stateStack.push(act.state);
            tokenIdx++;
        } 
        else if (act.type == ParserAction::REDUCE) {
            for (int i = 0; i < act.rhsSize; i++) {
                if (!stateStack.empty()) stateStack.pop();
            }
            
            if (stateStack.empty()) return false;

            int topState = stateStack.top();
            if (gotoTable[topState].find(act.lhs) == gotoTable[topState].end()) {
                cerr << "  [GOTO Error] No GOTO for " << act.lhs << " in State " << topState << endl;
                return false;
            }
            
            int nextState = gotoTable[topState][act.lhs];
            stateStack.push(nextState);
        } 
        else if (act.type == ParserAction::ACCEPT) {
            return true;
        }
    }
}