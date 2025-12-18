#include "SecurityAnalyzer.h"
#include <algorithm>
#include <cctype>

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

    // 0. Pre-Scan: Detecteer Scripting/HTML injectie (XSS Polyglots)
    string qLower = query;
    transform(qLower.begin(), qLower.end(), qLower.begin(), ::tolower);

    if (qLower.find("<script") != string::npos || 
        qLower.find("alert(") != string::npos || 
        qLower.find("javascript:") != string::npos) {
        addFinding(SEV_CRITICAL_HARD_BLOCK, "Non-SQL scripting fragment detected (Potential XSS/Polyglot).");
    }

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

        // tautologie detectie: OR gevolgd door tautologie patronen
        if (type == "T_OR" && ctx == SqlContext::WHERE) {
            
            // 1. SKIP HAAKJES (Deep Nesting Fix)
            // Dit fixt de bypass van OR(1=1) en deep nesting
            int offset = 1;
            while (i + offset < tokens.size() && tokens[i + offset].type == "T_LPAREN") {
                offset++;
            }

            // Safety check: niet buiten de vector lezen (fix voor dangling OR)
            if (i + offset >= tokens.size()) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "Dangling OR detected (Incomplete Query).");
                continue; 
            }

            Token nextToken = tokens[i + offset];
            string nextType = nextToken.type;
            string nextVal = nextToken.value;
            string nextUpper = nextVal;
            transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

            bool tautologyFound = false;

            // Strict Structurele check: OR gevolgd door Literal
            // Valide SQL na een OR begint bijna altijd met een kolomnaam (T_ID).
            bool isLiteral = (nextType == "T_INT" || nextType == "T_STRING" || 
                              nextType == "T_FLOAT" || nextType == "T_HEX");

            if (isLiteral) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, 
                    "Structural Violation: OR clause starts with Literal (" + nextToken.value + "). Expected Column Name.");
                tautologyFound = true;
            }

            // DETECTIE: CAST Bypass en Rekenkundige injectie
            if (nextType == "T_CAST" || nextUpper == "CAST") {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "High Risk: CAST function detected inside OR clause.");
                tautologyFound = true;
            }
            else if (nextType == "T_MINUS") {
                 addFinding(SEV_CRITICAL_HARD_BLOCK, "Suspicious arithmetic in OR clause (Negative value).");
                 tautologyFound = true;
            }

            // OR TRUE
            else if (nextUpper == "TRUE" || nextType == "T_BOOLEAN") {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "Tautology: OR TRUE detected.");
                tautologyFound = true;
            }
            // OR niet-nul
            else if (nextType == "T_INT" && nextVal != "0") {
                // Check of het gevolgd wordt door een vergelijking (bijv OR 1 = 5 is veilig)
                int nextOffset = offset + 1;
                bool isComparisonNext = false;
                if (i + nextOffset < tokens.size()) {
                    string tNext = tokens[i + nextOffset].type;
                    if (tNext == "T_EQ" || tNext == "T_LT" || tNext == "T_GT" || 
                        tNext == "T_NEQ" || tNext == "T_LTE" || tNext == "T_GTE") {
                        isComparisonNext = true;
                    }
                }
                
                if (!isComparisonNext) {
                    addFinding(SEV_CRITICAL_HARD_BLOCK, "Tautology: OR Non-Zero Value detected (" + nextVal + ").");
                    tautologyFound = true;
                }
            }

            // OR x=x, OR 1=1, OR 'a'='a', OR 1<2, ...
            else if (!tautologyFound && i + offset + 2 < tokens.size()) {
                Token t1 = tokens[i + offset];     // Links
                Token op = tokens[i + offset + 1]; // Operator
                Token t3 = tokens[i + offset + 2]; // Rechts

                bool isComparison = (op.type == "T_EQ" || op.type == "T_LT" || op.type == "T_GT" ||
                                     op.type == "T_LTE" || op.type == "T_GTE" || op.type == "T_NEQ");

                if (isComparison) {
                    // FIX: Normaliseer waarden (strip quotes van strings)
                    string v1_clean = t1.value;
                    string v3_clean = t3.value;
                    
                    if (v1_clean.size() >= 2 && (v1_clean.front() == '\'' || v1_clean.front() == '"')) 
                        v1_clean = v1_clean.substr(1, v1_clean.size()-2);
                    if (v3_clean.size() >= 2 && (v3_clean.front() == '\'' || v3_clean.front() == '"')) 
                        v3_clean = v3_clean.substr(1, v3_clean.size()-2);

                    // OR id=id (zelfde identifier)
                    if (t1.type == "T_ID" && t3.type == "T_ID" && v1_clean == v3_clean) {
                        addFinding(SEV_CRITICAL_HARD_BLOCK, 
                            "Tautology: OR " + v1_clean + "=" + v3_clean + " (Same Identifier).");
                        tautologyFound = true;
                    }

                    bool leftHasIdentifier = (t1.type == "T_ID");
                    bool rightHasIdentifier = (t3.type == "T_ID");

                    // Als we twee dingen vergelijken (Literals of Subqueries) zonder dat er een kolomnaam bij betrokken is:
                    if (!leftHasIdentifier && !rightHasIdentifier) {
                        addFinding(SEV_CRITICAL_HARD_BLOCK, 
                            "Logic Evasion Detected: Comparison between constants/subqueries without column reference.");
                    }
                }
            }

            // als geen specifieke tautologie gevonden werd, gewoon warning geven (Zero Trust)
            if (!tautologyFound) {
                if (role == ROLE_CLIENT) {
                    addFinding(SEV_CRITICAL_HARD_BLOCK, "OR operator strictly forbidden for Client.");
                } else if (role == ROLE_EMPLOYEE) {
                    addFinding(SEV_MEDIUM_PRIVILEGE, "OR operator usage monitoring.");
                } else {
                    addFinding(SEV_LOW_SUSPICIOUS, "Admin OR usage logged.");
                }
            }
        }

        // tautologie detectie: AND gevolgd door tautologie patronen
        if (type == "T_AND" && ctx == SqlContext::WHERE) {
            
            int offset = 1;
            while (i + offset < tokens.size() && tokens[i + offset].type == "T_LPAREN") {
                offset++;
            }

            if (i + offset + 2 < tokens.size()) {
                Token t1 = tokens[i + offset];     // Links
                Token op = tokens[i + offset + 1]; // Operator
                Token t3 = tokens[i + offset + 2]; // Rechts

                bool isComparison = (op.type == "T_EQ" || op.type == "T_LT" || op.type == "T_GT" ||
                                     op.type == "T_LTE" || op.type == "T_GTE" || op.type == "T_NEQ");

                if (isComparison) {
                    // Check: Literal vs Literal (bijv: AND 1=1, AND 'a'='a', AND 7340=7340)
                    // Dit is nutteloze logica in een WHERE clause en duidt op Blind SQLi.
                    
                    bool t1IsLit = (t1.type == "T_INT" || t1.type == "T_STRING" || t1.type == "T_FLOAT" || t1.type == "T_HEX");
                    bool t3IsLit = (t3.type == "T_INT" || t3.type == "T_STRING" || t3.type == "T_FLOAT" || t3.type == "T_HEX");

                    if (t1IsLit && t3IsLit) {
                        addFinding(SEV_CRITICAL_HARD_BLOCK, 
                            "Blind SQL Injection Pattern: Literal comparison in AND clause (" + t1.value + op.value + t3.value + ").");
                    }

                    bool leftHasIdentifier = (t1.type == "T_ID");
                    bool rightHasIdentifier = (t3.type == "T_ID");

                    if (!leftHasIdentifier && !rightHasIdentifier) {
                        addFinding(SEV_CRITICAL_HARD_BLOCK, 
                            "Logic Evasion Detected: Comparison between constants/subqueries without column reference.");
                    }
                }
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

        
        // A. Voorkom SELECT op gevoelige tabellen zonder filters (Client/Employee)
        if (type == "T_FROM" && role != ROLE_ADMIN) {
            for (size_t offset = 1; i + offset < tokens.size(); offset++) {
                string val = tokens[i+offset].value;
                transform(val.begin(), val.end(), val.begin(), ::toupper);
                
                // Als we een komma of een andere clause tegenkomen, stoppen we met zoeken naar tabelnamen
                if (tokens[i+offset].type == "T_WHERE" || tokens[i+offset].type == "T_PCOMMA") break;

                // Check of de tabelnaam (of een deel ervan na een punt) gevoelig is
                if (val == "USERS" || val == "PASSWORDS" || val == "SENSITIVE_DATA") {
                    bool hasWhere = false;
                    for (size_t j = i; j < tokens.size(); ++j) {
                        if (tokens[j].type == "T_WHERE") { hasWhere = true; break; }
                    }
                    if (!hasWhere) {
                        addFinding(SEV_HIGH_RISK, "Unfiltered access to sensitive table (" + val + ") denied.");
                    }
                }
            }
        }

       
        // System variables / fingerprinting
        if (type == "T_ID") {
            // A. Detecteer 'Non-ASCII' (Homoglyph protection)
            // Voorkomt dat UЅERS (met Cyrillische S) wordt gebruikt om filters te omzeilen.
            for (char c : value) {
                if (static_cast<unsigned char>(c) > 127) {
                    addFinding(SEV_CRITICAL_HARD_BLOCK, "Homoglyph attack detected: Non-ASCII character in identifier '" + value + "'.");
                    break;
                }
            }

            // B. System variables / fingerprinting
            // Controleert op @@variables en gevoelige systeemfuncties
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