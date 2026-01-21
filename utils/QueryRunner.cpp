#include "QueryRunner.h"

#include <iostream>
#include <filesystem>
#include <ranges>

#include "../LALR.h"
#include "../auth/RBACManager.h"
#include "../parser/LALRParser.h"
#include "../lexer/Lexer.h"
#include "../security/SecurityAnalyzer.h"
#include "../security/TaintAnalyzer.h"
#include "AuditLogger.h"

// Maakt gebruik van FNV-1a hash functie (Fowler–Noll–Vo)
uint64_t hashFile(const std::string& fileName) {
    std::ifstream file(fileName, std::ios::in | std::ios::binary);
    if(!file) {
        std::cout << "[System] Error opening file";
        return 0;
    }

    constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037;
    constexpr uint64_t FNV_PRIME = 1099511628211;

    uint64_t hash = FNV_OFFSET_BASIS;
    char buffer[4096];

    while(file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        for(std::streamsize i = 0; i < file.gcount(); i++) {
            hash ^= static_cast<unsigned char>(buffer[i]); // XOR hash met gelezen byte
            hash *= FNV_PRIME;
        }
    }

    return hash;
}

void ensureParseTable(const std::string& grammarFile, const std::string& tableFile) {
    bool needToGenerate = true;
    std::string hashFilename = grammarFile + ".hash";

    // Check op basis van de hash van de grammar om te zien of we opnieuw moeten genereren
    if (fs::exists(tableFile) && fs::exists(grammarFile) && fs::exists(hashFilename)) {
        // Lees de gesavede hash
        std::ifstream hf(hashFilename);
        uint64_t storedHash;
        hf >> storedHash;

        uint64_t currentHash = hashFile(grammarFile);

        // Vergelijk met de hash van de huidige grammar
        if(currentHash == storedHash) {
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

        // Save de nieuwe hash
        std::ofstream hf(hashFilename);
        hf << hashFile(grammarFile);
    }
}

void runCheck(const std::string& tableFile, const std::vector<std::string>& queries, UserRole role) {
    SimpleLexer lexer;
    LALRParser parser(tableFile);
    SecurityAnalyzer security;
    RBACManager rbac;

    AuditLogger logger("../analysis.log");
    std::string roleName = rbac.getRoleName(role);
    std::string short_roleName = roleName.substr(0,3);

    std::cout << "\n=======================================================" << std::endl;
    std::cout << "  USER ROLE: \033[1;36m" << rbac.getRoleName(role) << "\033[0m" << std::endl;
    std::cout << "=======================================================" << std::endl;

    int count = 1;
    for (const std::string& q : queries) {
        std::string queryId = roleName + "-" + std::to_string(count); // <<< 2) simpele ID
        std::cout << "\nQUERY " << count++ << ": " << q << std::endl;
        
        std::vector<Token> tokens = lexer.tokenize(q);

        ASTNode* ast = parser.parse(tokens);
        bool validSyntax = (ast != nullptr);

        TaintAnalyzer taintAnalyzer;
        if (validSyntax && ast) {
            taintAnalyzer.analyze(ast);

            bool hasCriticalTaint = false;
            for (const auto& finding : taintAnalyzer.getFindings()) {
                if (finding.severity == SEV_CRITICAL_HARD_BLOCK) {
                    hasCriticalTaint = true;
                    break;
                }
            }

            if (hasCriticalTaint) {
                std::cout << ">>> ACTION: \033[1;31mBLOCKED BY TAINT ANALYSIS (Critical Taint Flow)\033[0m" << std::endl;
                std::cout << "-------------------------------------------------------" << std::endl;
                logger.log(queryId, roleName, "BLOCKED", "TAINT", q);
                continue;
            }
        }

        // 1. Security Check (Firewall)
        if (security.isDangerous(lexer, q, role)) {
            std::cout << ">>> ACTION: \033[1;31mBLOCKED BY FIREWALL (Security Violation)\033[0m" << std::endl;
            std::cout << "-------------------------------------------------------" << std::endl;
            logger.log(queryId, roleName, "BLOCKED", "FIREWALL", q);
            continue;
        }

        // 2. RBAC Check (Mag deze rol dit commando uitvoeren?
        if (!rbac.hasPermission(role, tokens)) {
            std::cout << ">>> ACTION: \033[1;31mDENIED (INSUFFICIENT PRIVILEGES)\033[0m" << std::endl;
            logger.log(queryId, roleName, "BLOCKED", "RBAC", q);
        }

        // 3. Syntax Check (Is het een valide query?)
        std::cout << "\n>>> FINAL REPORT:" << std::endl;
        if (validSyntax) {
            // Dit is het pad van volledig succes (Security + RBAC + Syntax)
            std::cout << ">>> ACTION: \033[1;32mALLOWED (Proceeding to Execution)\033[0m" << std::endl;
            std::cout << "  Access:           GRANTED" << std::endl;
            std::cout << "  Security Status: CLEAN" << std::endl;

            if (!taintAnalyzer.getFindings().empty()) {
                std::cout << "  Taint Status:    WARNINGS DETECTED" << std::endl;
            } else {
                std::cout << "  Taint Status:   CLEAN" << std::endl;
            }
            
            std::cout << "  Syntax Status:  VALID SQL" << std::endl;

            std::cout << "\n>>> AST: \n";
            logger.log(queryId, roleName, "ALLOWED", "OK", q);
            ast->print(2);
            ast->doorlopen(ast, count - 1, short_roleName);
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

            logger.log(queryId, roleName, "BLOCKED", "SYNTAX_ERROR", q);
        }
    }
}

void createQueryVector(std::vector<std::string> &queries, const std::string &queryFile) {
    std::string filename = "../" + queryFile;
    std::ifstream in(filename);
    json j;
    in >> j;
    const auto& q = j.at("Query");
    for (const auto& it : q) {
        queries.push_back(it.get<std::string>());
    }
}