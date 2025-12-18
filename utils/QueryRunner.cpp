#include "QueryRunner.h"

#include "../LALR.h"
#include "../auth/RBACManager.h"
#include "../parser/LALRParser.h"
#include "../lexer/Lexer.h"
#include "../security/SecurityAnalyzer.h"

string setupPathsAndGenerate() {
    
    // CMakeLists.txt
    string root = PROJECT_ROOT;
    
    // Definieer de grammatica en parsetable bestanden
    fs::path grammarPath = fs::path(root) / "CFG.json";
    fs::path tablePath = fs::path(root) / "parsetable.json";

    std::cout << "[System] Looking for grammar at: " << grammarPath << std::endl;

    // Zorg ervoor dat de parse tabel gegenereerd en up-to-date is
    ensureParseTable(grammarPath.string(), tablePath.string());

    return tablePath.string();
}

void ensureParseTable(const string& grammarFile, const string& tableFile) {
    bool needToGenerate = true;

    // Check op basis van timestamps om te zien of we opnieuw moeten genereren
    if (fs::exists(tableFile) && fs::exists(grammarFile)) {
        auto grammarTime = fs::last_write_time(grammarFile);
        auto tableTime = fs::last_write_time(tableFile);

        if (tableTime >= grammarTime) {
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