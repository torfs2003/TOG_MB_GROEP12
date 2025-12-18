#include "QueryRunner.h"

#include <iostream>
#include <filesystem>
#include "../LALR.h"
#include "../auth/RBACManager.h"
#include "../parser/LALRParser.h"
#include "../lexer/Lexer.h"
#include "../security/SecurityAnalyzer.h"

void ensureParseTable(const std::string& grammarFile, const std::string& tableFile) {
    bool needToGenerate = true;

    // Check op basis van timestamps om te zien of we opnieuw moeten genereren
    if (fs::exists(tableFile) && fs::exists(grammarFile)) {
        auto grammarTime = fs::last_write_time(grammarFile);
        auto tableTime = fs::last_write_time(tableFile);

        if (tableTime > grammarTime) {
            std::cout << "[System] Parse table is up to date. Skipping generation.\n";
            needToGenerate = false;
        } else {
            std::cout << "[System] Grammar file has changed. Regenerating parse table...\n";
        }
    } else {
        std::cout << "[System] Parse table not found. Generating...\n";
    }

    if (needToGenerate) {
        CFG cfg(grammarFile);
        cfg.toStates();      
        cfg.saveTableToJSON(tableFile);
    }
}

void runCheck(const std::string& tableFile, const std::vector<std::string>& queries, UserRole role) {
    SimpleLexer lexer;
    LALRParser parser(tableFile);
    SecurityAnalyzer security;
    RBACManager rbac;

    std::cout << "\n=======================================================" << std::endl;
    std::cout << "  USER ROLE: \033[1;36m" << rbac.getRoleName(role) << "\033[0m" << std::endl;
    std::cout << "=======================================================" << std::endl;

    int count = 1;
    for (const std::string& q : queries) {
        std::cout << "\nQUERY " << count++ << ": " << q << std::endl;
        
        std::vector<Token> tokens = lexer.tokenize(q);

        // 1. Security Check (Firewall)
        if (security.isDangerous(lexer, q, role)) {
            std::cout << ">>> ACTION: \033[1;31mBLOCKED BY FIREWALL (Security Violation)\033[0m" << std::endl;
            std::cout << "-------------------------------------------------------" << std::endl;
            continue; 
        } 

        // 2. RBAC Check (Mag deze rol dit commando uitvoeren?
        if (!rbac.hasPermission(role, tokens)) {
            std::cout << ">>> ACTION: \033[1;31mDENIED (INSUFFICIENT PRIVILEGES)\033[0m" << std::endl;
            continue; 
        }

        // 3. Syntax Check (Is het een valide query?)
        bool validSyntax = parser.parse(tokens); 

        std::cout << "\n>>> FINAL REPORT:" << std::endl;

        if (validSyntax) {
            // Dit is het pad van volledig succes (Security + RBAC + Syntax)
            std::cout << ">>> ACTION: \033[1;32mALLOWED (Proceeding to Execution)\033[0m" << std::endl; 
            std::cout << "  Access:           GRANTED" << std::endl;
            std::cout << "  Security Status: CLEAN" << std::endl;
            std::cout << "  Syntax Status:  VALID SQL" << std::endl;
        } else { 
            bool hadAlerts = !security.getLastFindings().empty(); 

            std::cout << ">>> ACTION: \033[1;31mBLOCKED (SYNTAX ERROR)\033[0m" << std::endl; 
            std::cout << "  Access:           BLOCKED" << std::endl;
            
            if (hadAlerts) {
                std::cout << "  Security Status: VIOLATION DETECTED" << std::endl; 
            } else { 
                std::cout << "  Security Status: CLEAN" << std::endl; 
            }
            std::cout << "  Syntax Status:  \033[1;31mINVALID SQL\033[0m" << std::endl;
        }
    }
}