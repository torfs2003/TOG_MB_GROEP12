#include "SecurityAnalyzer.h"
#include "common.h"

// Hulpfunctie om string naar uppercase te converteren
std::string toUpper(const std::string& str) {
    std::string upper = str;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    return upper;
}

bool SecurityAnalyzer::isDangerous(SimpleLexer& lexer, std::string query, UserRole role) {
    std::cout << "    [Security Scan] Scanning for attack patterns (Context-Aware)..." << std::endl;

    // Resetten van de bevindingen voor deze query.
    this->findings.clear();

    // De 'addFinding' lambda moet de klasse-variabele gebruiken.
    auto addFinding = [&](AlertSeverity sev, const std::string& msg) {
        this->findings.push_back({sev, msg});
    };

    std::vector<Token> tokens = lexer.tokenize(query);

    SqlContext ctx = SqlContext::NONE;
    auto updateContext = [&](const std::string& t) {
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
            addFinding(SEV_CRITICAL_HARD_BLOCK,
                         "Time-Based Function/Keyword (" + t.value + ") detected. DOS/Stealth risk.");
        }
    }


    // 3. Multi-statement detectie
    size_t firstSemicolon = query.find(";");
    size_t secondSemicolon = (firstSemicolon != std::string::npos) ? query.find(";", firstSemicolon + 1) : std::string::npos;

    if (secondSemicolon != std::string::npos) {
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
        std::string type = tokens[i].type;
        std::string value = tokens[i].value;
        std::string upperVal = toUpper(value);

        bool isHex = type == "T_HEX" || (value.size() > 2 && (value.substr(0,2) == "0x" || value.substr(0,2) == "0X"));

        if (type == "T_ID" || type == "T_STRING") { 
            if (upperVal.find("INFORMATION_SCHEMA") != std::string::npos || 
                upperVal.find("PG_CATALOG") != std::string::npos) {
                addFinding(SEV_HIGH_RISK, "System schema access detected (" + value + "). Possible enumeration.");
            }
        }

        // SELECT INTO detectie
        if (type == "T_INTO") {
            bool isSelectInto = false;
            // Loop terug om de start van de statement te vinden
            for (int k = i - 1; k >= 0; k--) {
                if (tokens[k].type == "T_SELECT") {
                    isSelectInto = true;
                    break;
                }
                if (tokens[k].type == "T_INSERT" || tokens[k].type == "T_UPDATE" || tokens[k].type == "T_DELETE") {
                    break; // Het is een INSERT INTO, dat is normaal
                }
                if (tokens[k].value == ";") break; // Einde vorige query
            }

            if (isSelectInto) {
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
            int offset = 1;
            while (i + offset < tokens.size() && tokens[i + offset].type == "T_LPAREN") {
                offset++;
            }

            if (i + offset >= tokens.size()) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "Dangling OR detected (Incomplete Query).");
                continue; 
            }

            Token tLeft = tokens[i + offset];
            std::string typeLeft = tLeft.type;
            std::string valLeft = tLeft.value;
            std::string upperLeft = toUpper(valLeft);

            bool tautologyFound = false;
            
            bool isLiteral = (typeLeft == "T_INT" || typeLeft == "T_STRING" || 
                              typeLeft == "T_FLOAT" || typeLeft == "T_HEX");

            if (isLiteral) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, 
                    "Structural Violation: OR clause starts with Literal (" + valLeft + "). Expected Column Name.");
                tautologyFound = true;
            }
            else if (typeLeft == "T_MINUS") {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "Suspicious arithmetic in OR clause (Negative value/Minus).");
                tautologyFound = true;
            }
            else if (upperLeft == "TRUE" || typeLeft == "T_BOOLEAN") {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "Tautology: OR TRUE detected.");
                tautologyFound = true;
            }
            else if (typeLeft == "T_CAST" || upperLeft == "CAST") {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "High Risk: CAST function detected inside OR clause.");
                tautologyFound = true;
            }

            else if (!tautologyFound && i + offset + 2 < tokens.size()) {
                Token t1 = tokens[i + offset];       // Links
                Token op = tokens[i + offset + 1];   // Operator
                Token t3 = tokens[i + offset + 2];   // Rechts

                bool isComparison = (op.type == "T_EQ" || op.type == "T_LT" || op.type == "T_GT" ||
                                     op.type == "T_LTE" || op.type == "T_GTE" || op.type == "T_NEQ");

                if (isComparison) {
                    std::string v1_clean = t1.value;
                    std::string v3_clean = t3.value;
                    
                    if (v1_clean.size() >= 2 && (v1_clean.front() == '\'' || v1_clean.front() == '"')) 
                        v1_clean = v1_clean.substr(1, v1_clean.size()-2);
                    if (v3_clean.size() >= 2 && (v3_clean.front() == '\'' || v3_clean.front() == '"')) 
                        v3_clean = v3_clean.substr(1, v3_clean.size()-2);

                    // A. Check: OR id = id
                    if (t1.type == "T_ID" && t3.type == "T_ID" && v1_clean == v3_clean) {
                        addFinding(SEV_CRITICAL_HARD_BLOCK, 
                            "Tautology: OR " + v1_clean + "=" + v3_clean + " (Same Identifier).");
                        tautologyFound = true;
                    }
                    // B. Check: OR 'a' = 'a'
                    else if (v1_clean == v3_clean && (t1.type == "T_INT" || t1.type == "T_STRING")) {
                        addFinding(SEV_CRITICAL_HARD_BLOCK, 
                            "Tautology: OR " + v1_clean + op.value + v3_clean + " (Same Literals).");
                        tautologyFound = true;
                    }
                    // C. Check: Wiskundige Tautologie (1 < 2)
                    else if (t1.type == "T_INT" && t3.type == "T_INT") {
                        try {
                            long left = stol(v1_clean);
                            long right = stol(v3_clean);
                            bool alwaysTrue = false;
                            if (op.type == "T_LT" && left < right) alwaysTrue = true;
                            else if (op.type == "T_GT" && left > right) alwaysTrue = true;
                            else if (op.type == "T_LTE" && left <= right) alwaysTrue = true;
                            else if (op.type == "T_GTE" && left >= right) alwaysTrue = true;
                            else if (op.type == "T_NEQ" && left != right) alwaysTrue = true;

                            if (alwaysTrue) {
                                addFinding(SEV_CRITICAL_HARD_BLOCK, 
                                    "Mathematical Tautology: OR " + v1_clean + op.value + v3_clean + " is always true.");
                                tautologyFound = true;
                            }
                        } catch (...) { /* Ignore parse errors */ }
                    }
                    // D. Check: Logic Evasion
                    if (!tautologyFound) {
                        bool leftHasIdentifier = (t1.type == "T_ID");
                        bool rightHasIdentifier = (t3.type == "T_ID");
                        if (!leftHasIdentifier && !rightHasIdentifier) {
                            addFinding(SEV_CRITICAL_HARD_BLOCK, 
                                "Logic Evasion Detected: Comparison between constants without column reference.");
                            tautologyFound = true;
                        }
                    }
                }
            }
            if (!tautologyFound) {
                if (role == ROLE_CLIENT) {
                    addFinding(SEV_CRITICAL_HARD_BLOCK, "OR operator strictly forbidden for Client.");
                } else {
                    addFinding(SEV_LOW_SUSPICIOUS, "Admin OR usage logged.");
                }
            }
        }

        // TAUTOLOGIE DETECTIE: AND
        if (type == "T_AND" && ctx == SqlContext::WHERE) {
            int offset = 1;
            while (i + offset < tokens.size() && tokens[i + offset].type == "T_LPAREN") {
                offset++;
            }
            if (i + offset + 2 < tokens.size()) {
                Token t1 = tokens[i + offset];
                Token op = tokens[i + offset + 1];
                Token t3 = tokens[i + offset + 2];
                bool isComparison = (op.type == "T_EQ" || op.type == "T_LT" || op.type == "T_GT" ||
                                     op.type == "T_LTE" || op.type == "T_GTE" || op.type == "T_NEQ");

                if (isComparison) {
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

        // System variables / fingerprinting
        if (type == "T_ID") {
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
    if ((query.find("'--") != std::string::npos || query.find("'/*") != std::string::npos) && role != ROLE_ADMIN) {
        addFinding(SEV_HIGH_RISK, "String terminated before comment. Possible truncation attack.");
    }

    // 7. Risk scoring
    if (this->findings.empty()) {
        std::cout << "    [Security Scan] No obvious signatures found." << std::endl;
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
        if (f.severity <= SEV_HIGH_RISK) {
            std::cout << "  --> \033[1;31m[ALERT]\033[0m " << f.message << std::endl;
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
