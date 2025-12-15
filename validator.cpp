#include "validator.h" 


/* "De Security Scanner implementeert detectie voor alle SQL Injection vectoren 
gedocumenteerd door W3Schools (Tautologies, End-of-Line injecties, Stacked Queries) en 
breidt dit uit met bescherming tegen geavanceerde technieken zoals Time-Based Blind 
SQLi, Hex-encoding obfuscation en System Variable Fingerprinting*/

const unordered_set<string> dangerous_keywords = {
    "T_DROP", "T_TRUNCATE", "T_ALTER", "T_INSERT", "T_UPDATE", "T_DELETE", 
    "T_PROCEDURE", "T_CREATE", "T_BACKUP"
};

const unordered_set<string> time_based_functions = {
    "SLEEP", "WAITFOR", "BENCHMARK"
};

// Mapping van SQL keywords naar Token types
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
    keywords["DEFERRABLE"] = "T_DEFERRABLE";
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
    keywords["UUID"] = "T_UUID";
    keywords["BYTEA"] = "T_BYTEA";
    keywords["INTERVAL"] = "T_INTERVAL";
    keywords["GEOMETRY"] = "T_GEOMETRY";
    keywords["MONEY"] = "T_MONEY";
    keywords["SMALLINT"] = "T_SMALLINT";
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
    keywords["MINUS"] = "T_MINUS_KEYWORD";
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
    // Mapping van leestekens
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
        if (isspace(c)) { i++; continue; }

        // Skip multiline comments /* ... */
        if (c == '/' && i + 1 < input.length() && input[i+1] == '*') {
            i += 2; 
            while (i < input.length()) {
                if (input[i] == '*' && i + 1 < input.length() && input[i+1] == '/') {
                    i += 2; 
                    break;
                }
                i++;
            }
            continue; 
        }

        // Skip single line comments -- ...
        if (c == '-' && i + 1 < input.length() && input[i+1] == '-') {
            while (i < input.length() && input[i] != '\n') {
                i++; 
            }
            continue; 
        }

       // Strings ("...")
        if (c == '"') {
            string val;
            i++; 
            while (i < input.length()) {
                if (input[i] == '"') {
                    if (i + 1 < input.length() && input[i+1] == '"') {
                        val += '"'; // Escaped quote in SQL
                        i += 2;
                    } else {
                        i++;
                        break;
                    }
                } else {
                    val += input[i++];
                }
            }
            tokens.push_back({"T_ID", val}); 
            continue;
        }

        // Hexadecimale getallen (0x...) - Vaak gebruikt voor obfuscation
        if (c == '0' && i + 1 < input.length() && (input[i+1] == 'x' || input[i+1] == 'X')) {
            string hexStr = "0x";
            i += 2; 
            while (i < input.length() && isxdigit(input[i])) {
                hexStr += input[i++];
            }
            tokens.push_back({"T_INT", hexStr});
            continue;
        }

        // Getallen
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

        // Identifiers en Keywords
        if (isalpha(c) || c == '_' || c == '@') { 
            string word;
            while (i < input.length() && (isalnum(input[i]) || input[i] == '_' || input[i] == '@')) {
                word += input[i++];
            }
            
            string upper = word;
            transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

            // Speciale gevallen voor gecombineerde keywords
            if (upper == "NOT") {
                int tempI = i;
                while (tempI < input.length() && isspace(input[tempI])) tempI++;

                if (tempI < input.length() && (isalpha(input[tempI]) || input[tempI] == '_')) {
                    string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    string nextUpper = nextWord;
                    transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

                    if (nextUpper == "IN") {
                        tokens.push_back({"T_NOT_IN", "NOT IN"});
                        i = tempI; 
                        continue;
                    } 
                    else if (nextUpper == "LIKE") {
                        tokens.push_back({"T_NOT_LIKE", "NOT LIKE"});
                        i = tempI;
                        continue;
                    } 
                    else if (nextUpper == "NULL") {
                        tokens.push_back({"T_NOT_NULL", "NOT NULL"});
                        i = tempI;
                        continue;
                    }
                }
            }

            // PRIMARY KEY detectie
            if (upper == "PRIMARY") {
                int tempI = i; 
                while (tempI < input.length() && isspace(input[tempI])) tempI++;

                if (tempI < input.length() && (isalpha(input[tempI]) || input[tempI] == '_')) {
                    string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    string nextUpper = nextWord;
                    transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

                    if (nextUpper == "KEY") {
                        tokens.push_back({"T_PK", "PRIMARY KEY"});
                        i = tempI; 
                        continue; 
                    }
                }
            }

            // FOREIGN KEY detectie
            if (upper == "FOREIGN") {
                int tempI = i; 
                while (tempI < input.length() && isspace(input[tempI])) tempI++;

                if (tempI < input.length() && (isalpha(input[tempI]) || input[tempI] == '_')) {
                    string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    string nextUpper = nextWord;
                    transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

                    if (nextUpper == "KEY") {
                        tokens.push_back({"T_FK", "FOREIGN KEY"});
                        i = tempI; 
                        continue; 
                    }
                }
            }

            if (keywords.count(upper)) {
                tokens.push_back({keywords[upper], word});
            } else {
                tokens.push_back({"T_ID", word});
            }
            continue;
        }
      
        // Single quoted strings ('...')
        if (c == '\'') {
            string s;
            i++;
            while (i < input.length()) {
                if (input[i] == '\'' && i + 1 < input.length() && input[i+1] == '\'') {
                    s += "'";  
                    i += 2;    
                } 
                else if (input[i] == '\'') {
                    i++; 
                    break;
                } 
                else {
                    s += input[i++];
                }
            }
            tokens.push_back({"T_STRING", s});
            continue;
        }

        // Symbolen en operators
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

string RBACManager::getRoleName(UserRole role) {
    switch(role) {
        case ROLE_CLIENT:   return "CLIENT [R--] (Select Only)";
        case ROLE_EMPLOYEE: return "EMPLOYEE [RW-] (Select, Insert, Update, Delete)";
        case ROLE_ADMIN:    return "ADMIN [RWX] (Full Control / DDL)";
        default:            return "UNKNOWN";
    }
}

// Controleert permissies op basis van het eerste commando in de query
bool RBACManager::hasPermission(UserRole role, const vector<Token>& tokens) {
    if (tokens.empty()) return false;

    string command = "";
    for(const auto& t : tokens) {
        if (t.type != "T_EOF" && t.type != "$") {
            command = t.type;
            break;
        }
    }
    
    bool isRead = (command == "T_SELECT" || command == "T_WITH" || command == "T_VALUES");
    
    bool isWrite = (command == "T_INSERT" || command == "T_UPDATE" || command == "T_DELETE");
    
    bool isAdmin = (command == "T_DROP" || command == "T_CREATE" || command == "T_ALTER" || 
                    command == "T_TRUNCATE" || command == "T_BACKUP" || command == "T_PROCEDURE");

    if (role == ROLE_ADMIN) {
        return true; 
    }

    if (role == ROLE_EMPLOYEE) {
        if (isRead || isWrite) return true;
        if (isAdmin) return false;
    }

    if (role == ROLE_CLIENT) {
        if (isRead) return true;
        if (isWrite || isAdmin) return false;
    }

    return false;
}

LALRParser::LALRParser(string filename) {
    ifstream f(filename);
    if (!f.is_open()) {
        cerr << "Error: Could not open " << filename << endl;
        exit(1);
    }
    json j;
    f >> j;

    // Laad de Action Table
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

    // Laad de Goto Table
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

        // Als er geen actie is voor dit symbool in de huidige state: Error
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

            // Probeer te herstellen bij een puntkomma (;)
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

            // Bij een puntkomma is de query afgerond
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

bool SecurityAnalyzer::isDangerous(SimpleLexer& lexer, string query, UserRole role) {
    cout << "   [Security Scan] Scanning for attack patterns (Optimized for broad CFG)..." << endl;
    
    bool dangerous = false;

    // Detecteer comments die vaak gebruikt worden om syntax checks te omzeilen
    if (query.find("--") != string::npos || query.find("/*") != string::npos) {
        cout << "   --> \033[1;31m[ALERT]\033[0m Suspicious Comment found ('--' or '/*'). Possible truncation attack." << endl;
        dangerous = true;
    }
    // Detecteer toegang tot systeem tabellen
    if (query.find("information_schema") != string::npos || 
        query.find("pg_catalog") != string::npos) {
        cout << "   --> \033[1;31m[ALERT]\033[0m System Schema Access detected. Risk of enumeration." << endl;
        dangerous = true;
    }

    vector<Token> tokens = lexer.tokenize(query);
    
    for (size_t i = 0; i < tokens.size(); i++) {
        string type = tokens[i].type;
        string value = tokens[i].value;

        // Detecteer Tautologies (bv: 1=1 of 'a'='a')
        if (i + 2 < tokens.size()) {
            string t1 = tokens[i].type;
            string t2 = tokens[i+1].type;
            string t3 = tokens[i+2].type;

            bool isLiteral1 = (t1 == "T_INT" || t1 == "T_STRING");
            bool isLiteral2 = (t3 == "T_INT" || t3 == "T_STRING");

            if (isLiteral1 && t2 == "T_EQ" && isLiteral2) {
                if (tokens[i].value == tokens[i+2].value) {
                     cout << "   --> \033[1;31m[ALERT]\033[0m Tautology detected ('" 
                          << tokens[i].value << "=" << tokens[i+2].value 
                          << "'). Possible authentication bypass." << endl;
                     dangerous = true;
                }
            }
        }

        // Detecteer Stacked Queries (meerdere commando's)
        if (type == "T_PCOMMA") {
            if (i + 1 < tokens.size() && tokens[i+1].type != "T_EOF" && tokens[i+1].type != "$") {
                cout << "   --> \033[1;31m[ALERT]\033[0m Stacked Query detected (';' followed by command). Possible command injection." << endl;
                dangerous = true;
            }
        }

        // Detecteer logische negatie, vaak gebruikt voor bypass
        if (type == "T_OR" && i + 1 < tokens.size() && tokens[i+1].type == "T_NOT") {
            cout << "   --> \033[1;31m[ALERT]\033[0m Logical Negation ('OR NOT') detected. Possible filter bypass." << endl;
            dangerous = true;
        }

        // Check op gevaarlijke keywords
        if (dangerous_keywords.count(type)) {
            if (role == ROLE_ADMIN) {
                continue; 
            } else {
                cout << "   --> \033[1;31m[ALERT]\033[0m High-risk DDL/DML keyword (" << value << ") detected. Policy Violation." << endl;
                dangerous = true;
            }
        }
        
        if (type == "T_ID") {
            string upperValue = value;
            transform(upperValue.begin(), upperValue.end(), upperValue.begin(), ::toupper);
            
            // Detecteer Time-Based functies (DoS risico)
            if (time_based_functions.count(upperValue)) {
                cout << "   --> \033[1;31m[ALERT]\033[0m Time-Based Function (" << upperValue << ") detected. DOS/Stealth risk." << endl;
                dangerous = true;
            }

            // Detecteer System Variables (@@version)
            if (value.size() >= 2 && value.substr(0, 2) == "@@") {
                cout << "   --> \033[1;31m[ALERT]\033[0m System Variable / Version fingerprinting detected (" << value << ")." << endl;
                dangerous = true;
            }
        }

        // Detecteer Hex Encoding (0x...)
        if (type == "T_INT" || type == "T_STRING") {
            if (value.size() > 2 && (value.substr(0, 2) == "0x" || value.substr(0, 2) == "0X")) {
                cout << "   --> \033[1;31m[ALERT]\033[0m Hexadecimal Literal detected. Possible payload obfuscation." << endl;
                dangerous = true;
            }
        }
        
        // UNION attacks
        if (type == "T_UNION") {
            cout << "   --> \033[1;31m[ALERT]\033[0m 'UNION' detected. Possible data exfiltration." << endl;
            dangerous = true;
        }

        // Gevallen opvangen wanneer "INTO" wordt gebruikt als aanval
        if (type == "T_INTO") {
            if (!tokens.empty()) {
                string firstCommand = tokens[0].type;

                if (firstCommand == "T_SELECT" || firstCommand == "T_WITH") {
                    cout << "   --> \033[1;31m[ALERT]\033[0m 'SELECT ... INTO' detected. Unauthorized table creation." << endl;
                    dangerous = true;
                }
            }
        }


    }

    if (!dangerous) {
        cout << "   [Security Scan] No obvious signatures found." << endl;
    }
    return dangerous;
}

void ensureParseTable(const string& grammarFile, const string& tableFile) {
    bool needToGenerate = true;

    // Check op basis van timestamps om te zien of we opnieuw moeten genereren
    if (fs::exists(tableFile) && fs::exists(grammarFile)) {
        auto grammarTime = fs::last_write_time(grammarFile);
        auto tableTime = fs::last_write_time(tableFile);

        if (tableTime > grammarTime) {
            cout << "[System] Parse table is up to date. Skipping generation.\n";
            needToGenerate = false;
        } else {
            cout << "[System] Grammar file has changed. Regenerating parse table...\n";
        }
    } else {
        cout << "[System] Parse table not found. Generating...\n";
    }

    if (needToGenerate) {
        CFG cfg(grammarFile);
        cfg.toStates();      
        cfg.saveTableToJSON(tableFile);
    }
}

void runCheck(const string& tableFile, const vector<string>& queries, UserRole role) {
    SimpleLexer lexer;
    LALRParser parser(tableFile);
    SecurityAnalyzer security;
    RBACManager rbac;

    cout << "\n=======================================================" << endl;
    cout << "   USER ROLE: \033[1;36m" << rbac.getRoleName(role) << "\033[0m" << endl;
    cout << "=======================================================" << endl;

    int count = 1;
    for (const string& q : queries) {
        cout << "\nQUERY " << count++ << ": " << q << endl;
        
        vector<Token> tokens = lexer.tokenize(q);

        // 1. RBAC Check (Mag deze rol dit commando uitvoeren?)
        if (!rbac.hasPermission(role, tokens)) {
            cout << ">>> ACTION: \033[1;31mDENIED (INSUFFICIENT PRIVILEGES)\033[0m" << endl;
            continue; 
        }

        // 2. Security Check (Zit er een injectie in?)
        bool isRisk = security.isDangerous(lexer, q, role);
        
        if (isRisk) {
            cout << ">>> ACTION: \033[1;31mBLOCKED BY FIREWALL (Security Violation)\033[0m" << endl;
            cout << "-------------------------------------------------------" << endl;
            continue; 
        } 

        // 3. Syntax Check (Is het valide SQL?)
        cout << ">>> ACTION: \033[1;32mALLOWED (Proceeding to Execution)\033[0m" << endl;
        bool validSyntax = parser.parse(tokens);

        cout << "\n>>> FINAL REPORT:" << endl;
        cout << "    Access:          GRANTED" << endl;
        cout << "    Security Status: CLEAN" << endl;
        cout << "    Syntax Status:   " << (validSyntax ? "VALID SQL" : "INVALID SQL") << endl;
    }
}