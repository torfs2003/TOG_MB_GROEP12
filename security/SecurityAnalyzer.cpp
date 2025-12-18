#include "SecurityAnalyzer.h"

#include <algorithm>
#include <iostream>

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


    // 2. System schema toegang
    std::string qUpper = query;
    transform(qUpper.begin(), qUpper.end(), qUpper.begin(), ::toupper);
    if (qUpper.find("INFORMATION_SCHEMA") != std::string::npos ||
        qUpper.find("PG_CATALOG") != std::string::npos) {
        addFinding(SEV_HIGH_RISK, "System schema access detected. Possible enumeration.");
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

        bool isHex = type == "T_HEX" || (value.size() > 2 && (value.substr(0,2) == "0x" || value.substr(0,2) == "0X"));


        // SELECT INTO detectie
        if (type == "T_INTO") {
            std::string firstCmd = tokens.front().type;
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
        if (type == "T_OR" && ctx == SqlContext::WHERE && i + 1 < tokens.size()) {
            std::string nextType = tokens[i+1].type;
            std::string nextVal = tokens[i+1].value;
            std::string nextUpper = nextVal;
            transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

            bool tautologyFound = false;

            // OR TRUE
            if (nextUpper == "TRUE" || nextType == "T_BOOLEAN") {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "Tautology: OR TRUE detected.");
                tautologyFound = true;
            }
            // OR niet-nul
            else if (nextType == "T_INT" && nextVal != "0" &&
                     (i + 2 >= tokens.size() ||
                      (tokens[i+2].type != "T_EQ" && tokens[i+2].type != "T_LT" &&
                       tokens[i+2].type != "T_GT" && tokens[i+2].type != "T_NEQ" &&
                       tokens[i+2].type != "T_LTE" && tokens[i+2].type != "T_GTE"))) {
                addFinding(SEV_CRITICAL_HARD_BLOCK, "Tautology: OR " + nextVal + " non-zero detected.");
                tautologyFound = true;
            }
            // OR x=x, OR 1=1, OR 'a'='a', OR 1<2, ...
            else if (i + 3 < tokens.size()) {
                std::string t1 = tokens[i+1].type;
                std::string t2 = tokens[i+2].type;
                std::string t3 = tokens[i+3].type;
                std::string v1 = tokens[i+1].value;
                std::string v3 = tokens[i+3].value;

                bool isComparison = (t2 == "T_EQ" || t2 == "T_LT" || t2 == "T_GT" ||
                                     t2 == "T_LTE" || t2 == "T_GTE" || t2 == "T_NEQ");

                if (isComparison) {
                    // OR literal=literal (1=1, 'a'='a')
                    if (t1 == t3 && v1 == v3 && (t1 == "T_INT" || t1 == "T_STRING" || t1 == "T_FLOAT")) {
                        addFinding(SEV_CRITICAL_HARD_BLOCK,
                            "Tautology: OR " + v1 + tokens[i+2].value + v3 + " (same literals)");
                        tautologyFound = true;
                    }
                    // OR id=id (zelfde identifier)
                    else if (t1 == "T_ID" && t3 == "T_ID" && v1 == v3) {
                        addFinding(SEV_CRITICAL_HARD_BLOCK,
                            "Tautology: OR " + v1 + "=" + v3 + " (same identifier)");
                        tautologyFound = true;
                    }
                    // OR 1<2, OR 2>1 (altijd-true vergelijkingen)
                    else if (t1 == "T_INT" && t3 == "T_INT") {
                        int left = stoi(v1);
                        int right = stoi(v3);
                        bool alwaysTrue = false;

                        if (t2 == "T_LT" && left < right) alwaysTrue = true;
                        else if (t2 == "T_GT" && left > right) alwaysTrue = true;
                        else if (t2 == "T_LTE" && left <= right) alwaysTrue = true;
                        else if (t2 == "T_GTE" && left >= right) alwaysTrue = true;
                        else if (t2 == "T_NEQ" && left != right) alwaysTrue = true;

                        if (alwaysTrue) {
                            addFinding(SEV_CRITICAL_HARD_BLOCK,
                                "Tautology: OR " + v1 + tokens[i+2].value + v3 + " (always true)");
                            tautologyFound = true;
                        }
                    }
                }
            }

            // als geen specifieke tautologie gevonden werd, gewoon warning geven
            if (!tautologyFound) {
                if (role == ROLE_CLIENT) {
                    addFinding(SEV_HIGH_RISK, "OR operator in WHERE clause. Potential boolean-based SQLi.");
                } else if (role == ROLE_EMPLOYEE) {
                    addFinding(SEV_MEDIUM_PRIVILEGE, "OR operator in WHERE clause (Employee). Monitor for SQLi.");
                } else {
                    addFinding(SEV_LOW_SUSPICIOUS, "OR operator in WHERE clause (Admin).");
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
            std::string upperVal = value;
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
