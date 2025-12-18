#include "validator.h" 

/* "De Security Scanner implementeert detectie voor alle SQL Injection vectoren 
gedocumenteerd door W3Schools (Tautologies, End-of-Line injecties, Stacked Queries) en 
breidt dit uit met bescherming tegen geavanceerde technieken zoals Time-Based Blind 
SQLi, Hex-encoding obfuscation en System Variable Fingerprinting*/


// DDL - ALLEEN ADMIN
static const unordered_set<string> DDL_KEYWORDS = {
    "T_DROP", "T_TRUNCATE", "T_ALTER", "T_CREATE", 
    "T_PROCEDURE", "T_BACKUP", "T_GRANT", "T_REVOKE"
};

// DML - EMPLOYEE & ADMIN
static const unordered_set<string> DML_KEYWORDS = {
    "T_INSERT", "T_UPDATE", "T_DELETE"
};

// Functies gebruikt voor MySQL Time-Based Blind SQL Injections
static const unordered_set<string> TIME_BASED_FUNCTIONS = {
    "T_SLEEP", "T_BENCHMARK" 
};

enum class SqlContext {
    NONE,
    SELECT_LIST,
    FROM,
    WHERE,
    JOIN_ON,
    GROUP_BY,
    HAVING,
    ORDER_BY,
    INSERT_VALUES,
    UPDATE_SET
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
    keywords["GRANT"]  = "T_GRANT";
    keywords["REVOKE"] = "T_REVOKE";
    keywords["TO"]     = "T_TO";
    keywords["WAITFOR"]   = "T_WAITFOR";
    keywords["DELAY"]     = "T_DELAY";
    keywords["SLEEP"]     = "T_SLEEP";
    keywords["BENCHMARK"] = "T_BENCHMARK";
    keywords["XOR"]       = "T_XOR";
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
    keywords["LIMIT"] = "T_LIMIT";
    keywords["OFFSET"] = "T_OFFSET";
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
    keywords["DATABASE"] = "T_DATABASE";
    keywords["WAITFOR"] = "T_WAITFOR";
    keywords["DELAY"] = "T_DELAY";
    keywords["USER"] = "T_USER";
    keywords["VALUE"] = "T_VALUE";
    keywords["NAME"] = "T_NAME";

    // Mapping van leestekens
    symbols['*'] = "T_STAR";    symbols[','] = "T_COMMA";
    symbols[';'] = "T_PCOMMA";  symbols['('] = "T_LPAREN";
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

        // Identifiers met dubbele aanhalingstekens ("...")
        if (c == '"') {
            string val;
            i++; 
            while (i < input.length()) {
                if (input[i] == '"') {
                    if (i + 1 < input.length() && input[i+1] == '"') {
                        val += '"';
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

        // Identifiers met Backticks (`)
        if (c == '`') {
            string val;
            i++; 
            while (i < input.length()) {
                if (input[i] == '`') {
                    if (i + 1 < input.length() && input[i+1] == '`') {
                        val += '`';
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


        // Hexadecimale getallen (0x...)
        if (c == '0' && i + 1 < input.length() && (input[i+1] == 'x' || input[i+1] == 'X')) {
            string hexStr = "0x";
            i += 2; 
            while (i < input.length() && isxdigit(input[i])) {
                hexStr += input[i++];
            }
            tokens.push_back({"T_HEX", hexStr}); 
            continue;
        }

        // Placeholder (?)
        if (c == '?') {
            tokens.push_back({"T_PLACEHOLDER", "?"});
            i++;
            continue;
        }

        //  Tijd Literalen
        bool isTimeStart = false;
        if (isdigit(c)) {
            // Check voor H:MM
            if (i + 1 < input.length() && input[i+1] == ':') {
                isTimeStart = true;
            }
            // Check voor HH:MM
            else if (i + 2 < input.length() && isdigit(input[i+1]) && input[i+2] == ':') {
                isTimeStart = true;
            }
        }

        if (isTimeStart) {
            string timeStr;
            int k = i;
            int colonCount = 0;
            
            // Scan voor het volledige mogelijke tijdspatroon
            while (k < input.length() && (isdigit(input[k]) || input[k] == ':' || input[k] == '.')) {
                if (input[k] == ':') colonCount++;
                timeStr += input[k++];
            }
            
            char last = timeStr.back();
            if (colonCount >= 1 && last != ':' && last != '.') { 
                tokens.push_back({"T_TIME_LITERAL", timeStr});
                i = k;
                continue;
            }
        }

        // Getallen
        bool isNumberStart = isdigit(c);
        if (!isNumberStart && (c == '+' || c == '-') && i + 1 < input.length() && isdigit(input[i+1])) {
             isNumberStart = true;
        }

        if (isNumberStart) {
            string num;
            bool isFloat = false;
            
            if (c == '+' || c == '-') {
                num += c;
                i++;
            }

            while (i < input.length()) {
                char next = input[i];
                
                if (isdigit(next)) {
                    num += next;
                    i++;
                } 
                else if (next == '.') {
                    isFloat = true;
                    num += next;
                    i++;
                }
                // Scientific Notation (E-notatie)
                else if (next == 'e' || next == 'E') {
                    isFloat = true;
                    num += next;
                    i++;
                    if (i < input.length() && (input[i] == '+' || input[i] == '-')) {
                        num += input[i++];
                    }
                } 
                else {
                    break;
                }
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

            // Speciale gevallen voor gecombineerde keywords (Multi-word lookahead)
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
                        i = tempI; continue;
                    } 
                    else if (nextUpper == "LIKE") {
                        tokens.push_back({"T_NOT_LIKE", "NOT LIKE"});
                        i = tempI; continue;
                    } 
                    else if (nextUpper == "NULL") {
                        tokens.push_back({"T_NOT_NULL", "NOT NULL"});
                        i = tempI; continue;
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
                        i = tempI; continue; 
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
                        i = tempI; continue; 
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
                if (input[i] == '\\' && i + 1 < input.length()) {
                    s += input[i+1];
                    i += 2;
                    continue;
                }
                if (input[i] == '\'') {
                    if (i + 1 < input.length() && input[i+1] == '\'') {
                        s += "'";
                        i += 2;
                    } else {
                        i++; 
                        break;
                    }
                } else {
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

            // Afhandeling van enkelvoudige symbolen
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

RBACManager::RBACManager() {
    loadPermissions();
}

void RBACManager::loadPermissions() {
    
    // READ (DQL)
    unordered_set<string> readOps = {
        "T_SELECT", 
        "T_WITH",
        "T_VALUES"
    };

    // WRITE (DML)
    unordered_set<string> writeOps = {
        "T_INSERT", 
        "T_UPDATE", 
        "T_DELETE"
    };

    // ADMIN (DDL & System)
    unordered_set<string> adminOps = {
        "T_CREATE", 
        "T_DROP", 
        "T_ALTER", 
        "T_TRUNCATE", 
        "T_BACKUP",
        "T_PROCEDURE",
        "T_GRANT",
        "T_REVOKE"
    };

    // CLIENT: Mag alleen lezen
    permissions[ROLE_CLIENT] = readOps;

    // EMPLOYEE: Mag lezen + schrijven
    permissions[ROLE_EMPLOYEE] = readOps;
    permissions[ROLE_EMPLOYEE].insert(writeOps.begin(), writeOps.end());

    // ADMIN: Mag alles
    permissions[ROLE_ADMIN] = readOps;
    permissions[ROLE_ADMIN].insert(writeOps.begin(), writeOps.end());
    permissions[ROLE_ADMIN].insert(adminOps.begin(), adminOps.end());
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
        if (t.type == "T_LPAREN") continue;

        if (t.type != "T_EOF" && t.type != "$") {
            command = t.type;
            break;
        }
    }
    
    // Als er geen commando gevonden is, weiger toegang
    if (command == "") return false;

    if (permissions.count(role)) {
        if (permissions[role].count(command)) {
            return true;
        }
    }

    if (role == ROLE_ADMIN) return true;

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

                while(!stateStack.empty()) stateStack.pop();
                stateStack.push(0);
                
                tokenIdx++; 
                recoveryMode = false;
                currentQueryError = false;
                queryCount++;
                continue;
            } 
            else if (sym == "T_EOF" || sym == "$") {
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
                
                while(!stateStack.empty()) stateStack.pop();
                stateStack.push(0);
                
                recoveryMode = false;
                currentQueryError = false;
                queryCount++;

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
            return !globalError;
        }
    }
    return !globalError;
}

bool SecurityAnalyzer::isDangerous(SimpleLexer& lexer, string query, UserRole role) {
    cout << "    [Security Scan] Scanning for attack patterns (Context-Aware)..." << endl;

    // Resetten van de bevindingen voor deze query.
    this->findings.clear();
    
    // De 'addFinding' lambda moet de klasse-variabele gebruiken.
    auto addFinding = [&](AlertSeverity sev, const string& msg) {
        this->findings.push_back({sev, msg});
    };

    vector<Token> tokens = lexer.tokenize(query);

    SqlContext ctx = SqlContext::NONE;
    auto updateContext = [&](const string& t) {
        if (t == "T_SELECT") ctx = SqlContext::SELECT_LIST;
        else if (t == "T_FROM") ctx = SqlContext::FROM;
        else if (t == "T_WHERE") ctx = SqlContext::WHERE;
        else if (t == "T_ON") ctx = SqlContext::JOIN_ON;
        else if (t == "T_GROUP") ctx = SqlContext::GROUP_BY;
        else if (t == "T_HAVING") ctx = SqlContext::HAVING;
        else if (t == "T_ORDER") ctx = SqlContext::ORDER_BY;
        else if (t == "T_VALUES") ctx = SqlContext::INSERT_VALUES;
        else if (t == "T_SET") ctx = SqlContext::UPDATE_SET;
    };


    // 1. // Harde Blokkades (time-based functions)
    for (const auto& t : tokens) {
        if (t.type == "T_WAITFOR" || t.type == "T_DELAY" ||
            t.type == "T_SLEEP" || t.type == "T_BENCHMARK") {
            
            // ADMIN mag dit eventueel voor maintenance, anderen absoluut niet.
            if (role != ROLE_ADMIN) {
                addFinding(SEV_CRITICAL_HARD_BLOCK,
                           "Time-Based Function/Keyword (" + t.value + ") detected. DOS/Stealth risk.");
            } else {
                addFinding(SEV_LOW_SUSPICIOUS, 
                           "Time-Based Function detected (Admin). Permitted but logged.");
            }
        }
    }


    // 2. System schema toegang
    string qUpper = query;
    transform(qUpper.begin(), qUpper.end(), qUpper.begin(), ::toupper);
    if (qUpper.find("INFORMATION_SCHEMA") != string::npos ||
        qUpper.find("PG_CATALOG") != string::npos) {
        addFinding(SEV_HIGH_RISK, "System schema access detected. Possible enumeration.");
    }

    // 3. Multi-statement detectie
    size_t firstSemicolon = query.find(";");
    size_t secondSemicolon = (firstSemicolon != string::npos) ? query.find(";", firstSemicolon + 1) : string::npos; 

    if (secondSemicolon != string::npos) {
        if (role != ROLE_ADMIN) {
            addFinding(SEV_CRITICAL_HARD_BLOCK, "Multiple statements detected. Possible injection attempt.");
        }
        else {
            addFinding(SEV_LOW_SUSPICIOUS, "Multiple statements detected (Admin). Monitor for chaining risks.");
        }
    }

    // 4. Token-gebasseerde analyse
    for (size_t i = 0; i < tokens.size(); i++) {
        updateContext(tokens[i].type);
        string type = tokens[i].type;
        string value = tokens[i].value;

        bool isHex = type == "T_HEX" || (value.size() > 2 && (value.substr(0,2) == "0x" || value.substr(0,2) == "0X"));


        // SELECT INTO detectie
        if (type == "T_INTO") {
            string firstCmd = tokens.front().type;
            if (firstCmd == "T_LPAREN" && tokens.size() > 1) firstCmd = tokens[1].type;
            if (firstCmd == "T_SELECT" || firstCmd == "T_WITH") {
                if (role == ROLE_ADMIN) {
                    addFinding(SEV_LOW_SUSPICIOUS, "'SELECT INTO' detected. Allowed for ADMIN.");
                } else {
                    addFinding(SEV_HIGH_RISK, "'SELECT INTO' detected. Unauthorized table creation.");
                }
            }
            if (isHex) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "SELECT INTO with hex literal blocked.");
            }
        }

        if (type == "T_SELECT" && i > 0 && tokens[i-1].type == "T_LPAREN") {
            
            // Stap A: Bepaal of deze subquery in een 'veilige' filtercontext staat (EXISTS/IN)
            bool isSafeFilter = false;
            for (int j = i - 2; j >= 0; --j) {
                if (tokens[j].type == "T_EXISTS" || tokens[j].type == "T_IN" || tokens[j].type == "T_NOT_IN") {
                    isSafeFilter = true;
                    break;
                }
                if (tokens[j].type == "T_SELECT") break;
            }

            // Stap B: Blokkeren/waarschuwen als het GEEN veilige filter is.
            if (!isSafeFilter) {
                if (role == ROLE_CLIENT) {
                    addFinding(SEV_CRITICAL_HARD_BLOCK, "Complex Scalar Subquery detected. Hard block for read-only role."); 
                } else if (role == ROLE_EMPLOYEE) {
                    addFinding(SEV_HIGH_RISK, "Complex Scalar Subquery detected (Employee). High risk."); 
                }
            }
        }

        // Subquery/UNION detection
        if (type == "T_UNION") {
            if (role == ROLE_CLIENT) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "UNION operator detected. Hard block for read-only role.");
            } 
            else if (role == ROLE_EMPLOYEE) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "UNION operator detected. Hard block for employee.");
            } 
            else if (role == ROLE_ADMIN && (ctx == SqlContext::SELECT_LIST || ctx == SqlContext::WHERE)) {
                addFinding(SEV_LOW_SUSPICIOUS, "UNION operator in sensitive context (Admin). Monitor for exfiltration.");
            } 
            else {
                addFinding(SEV_LOW_SUSPICIOUS, "UNION operator detected (Admin).");
            }
        }


        // Bitwise/Boolean operators
        if (type == "T_XOR" || type == "T_PIPE" || type == "T_AMP" || type == "T_CARET") {
            if (role == ROLE_CLIENT) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, type + " (Bitwise) operator detected. Hard block for client role.");
            } else if (role == ROLE_EMPLOYEE) {
                addFinding(SEV_HIGH_RISK, type + " (Bitwise) operator detected (Employee). Obfuscation risk.");
            } else if (role == ROLE_ADMIN) {
                addFinding(SEV_LOW_SUSPICIOUS, type + " (Bitwise) operator detected (Admin). Monitor for obfuscation.");
            }
        }
        
        // mogelijke tautologie/Boolean SQLi vangen
        if (type == "T_OR" && ctx == SqlContext::WHERE) {
            if (role != ROLE_ADMIN) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "OR operator in WHERE clause. Potential boolean-based SQLi.");
            } else {
                addFinding(SEV_LOW_SUSPICIOUS, "OR operator in WHERE clause (Admin).");
            }
        }


        // Hex literalen (role-aware)
        if (isHex && (ctx == SqlContext::WHERE || ctx == SqlContext::INSERT_VALUES || ctx == SqlContext::UPDATE_SET || ctx == SqlContext::SELECT_LIST)) {
            if (role != ROLE_ADMIN) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "Hex literal in sensitive context. Possible obfuscation/payload.");
            } else {
                addFinding(SEV_LOW_SUSPICIOUS, "Hex literal detected (Admin).");
            }
        }

        // System variables / fingerprinting
        if (type == "T_ID") {
            string upperVal = value;
            transform(upperVal.begin(), upperVal.end(), upperVal.begin(), ::toupper);
            if (value.size() >= 2 && value.substr(0,2) == "@@") {
                addFinding(SEV_HIGH_RISK, "System variable access (" + value + ").");
            }
            if (upperVal == "VERSION" || upperVal == "DATABASE" || upperVal == "USER" ||
                upperVal == "CURRENT_USER" || upperVal == "SESSION_USER") {
                addFinding(SEV_HIGH_RISK, "System information function (" + upperVal + "()).");
            }
        }

        // WITH RECURSIVE (Common Table Expressions)
        if (type == "T_WITH") {
            bool isRecursive = false;
            for (size_t j = i + 1; j < tokens.size() && j < i + 5; j++) {
                if (tokens[j].type == "T_RECURSIVE") {
                    isRecursive = true;
                    break;
                }
            }
            
            if (isRecursive) {
                if (role != ROLE_ADMIN) {
                    addFinding(SEV_CRITICAL_HARD_BLOCK, "RECURSIVE CTE detected. Potential DOS risk or complex query bypass.");
                } else {
                    addFinding(SEV_LOW_SUSPICIOUS, "RECURSIVE CTE detected (Admin).");
                }
            }
        }
    }

    // 5. Privilege violations
    for (const auto& t : tokens) {
        if (DDL_KEYWORDS.count(t.type) && role != ROLE_ADMIN) {
            addFinding(SEV_MEDIUM_PRIVILEGE, "DDL keyword (" + t.value + ") used without ADMIN privileges.");
        }
        if (DML_KEYWORDS.count(t.type) && role == ROLE_CLIENT) {
            addFinding(SEV_MEDIUM_PRIVILEGE, "DML keyword (" + t.value + ") used by read-only role.");
        }
    }

    // 6. Comment truncation attacks
    bool insideQuote = false;
    for (size_t k = 0; k < query.length(); k++) {
        if (query[k] == '\'') {
            insideQuote = !insideQuote;
            
            // We hebben net een quote gesloten (insideQuote is nu false)
            // Kijk nu vooruit wat er volgt.
            if (!insideQuote) {
                size_t next = k + 1;
                // Skip witruimte
                while (next < query.length() && isspace(query[next])) next++;
                
                // Check of we nu een commentaar start zien (-- of /*)
                if (next + 1 < query.length()) {
                    bool isDashComment = (query[next] == '-' && query[next+1] == '-');
                    bool isBlockComment = (query[next] == '/' && query[next+1] == '*');
                    
                    if (isDashComment || isBlockComment) {
                        if (role != ROLE_ADMIN) {
                            addFinding(SEV_HIGH_RISK, "String terminated followed by comment. Truncation attack detected.");
                        }
                    }
                }
            }
        }
    }
    // 7. Risk scoring
    if (this->findings.empty()) { 
        cout << "    [Security Scan] No obvious signatures found." << endl;
        return false;
    }

    int riskScore = 0;
    auto score = [&](AlertSeverity s) {
        switch (s) {
            case SEV_CRITICAL_HARD_BLOCK: return 100;
            case SEV_HIGH_RISK: return 40;
            case SEV_MEDIUM_PRIVILEGE: return 20;
            case SEV_LOW_SUSPICIOUS: return 5;
        }
        return 0;
    };
    for (auto& f : this->findings) riskScore += score(f.severity); 

    // Alert display
    sort(this->findings.begin(), this->findings.end(), [](auto& a, auto& b){ return a.severity < b.severity; }); 
    for (auto& f : this->findings) { 
        if (f.severity >= SEV_HIGH_RISK) {
            cout << "  --> \033[1;31m[ALERT]\033[0m " << f.message << endl;
        }
    }

    bool hasCriticalBlock = false;
    for (auto& f : this->findings) { 
        if (f.severity == SEV_CRITICAL_HARD_BLOCK) {
            hasCriticalBlock = true;
            break;
        }
    }

    // FINALE BESLISSING
    if (hasCriticalBlock) return true;
    if (riskScore >= 40 && role != ROLE_ADMIN) return true;

    return false;
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
    cout << "  USER ROLE: \033[1;36m" << rbac.getRoleName(role) << "\033[0m" << endl;
    cout << "=======================================================" << endl;

    int count = 1;
    for (const string& q : queries) {
        cout << "\nQUERY " << count++ << ": " << q << endl;
        
        vector<Token> tokens = lexer.tokenize(q);

        // 1. Security Check (Firewall)
        if (security.isDangerous(lexer, q, role)) {
            cout << ">>> ACTION: \033[1;31mBLOCKED BY FIREWALL (Security Violation)\033[0m" << endl;
            cout << "-------------------------------------------------------" << endl;
            continue; 
        } 

        // 2. RBAC Check (Mag deze rol dit commando uitvoeren?
        if (!rbac.hasPermission(role, tokens)) {
            cout << ">>> ACTION: \033[1;31mDENIED (INSUFFICIENT PRIVILEGES)\033[0m" << endl;
            continue; 
        }

        // 3. Syntax Check (Is het een valide query?)
        bool validSyntax = parser.parse(tokens); 

        cout << "\n>>> FINAL REPORT:" << endl;

        if (validSyntax) {
            // Dit is het pad van volledig succes (Security + RBAC + Syntax)
            cout << ">>> ACTION: \033[1;32mALLOWED (Proceeding to Execution)\033[0m" << endl; 
            cout << "  Access:           GRANTED" << endl;
            cout << "  Security Status: CLEAN" << endl;
            cout << "  Syntax Status:  VALID SQL" << endl;
        } else { 
            bool hadAlerts = !security.getLastFindings().empty(); 

            cout << ">>> ACTION: \033[1;31mBLOCKED (SYNTAX ERROR)\033[0m" << endl; 
            cout << "  Access:           BLOCKED" << endl;
            
            if (hadAlerts) {
                cout << "  Security Status: VIOLATION DETECTED" << endl; 
            } else { 
                cout << "  Security Status: CLEAN" << endl; 
            }
            cout << "  Syntax Status:  \033[1;31mINVALID SQL\033[0m" << endl;
        }
    }
}