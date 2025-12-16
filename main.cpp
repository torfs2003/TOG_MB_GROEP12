#include "validator.h"
#include "common.h"

int main() {
    // Definieer de grammatica en parsetable bestanden
    const string grammarFile = "CFG.json";
    const string tableFile = "parsetable.json";
    
    // Zorg ervoor dat de parse tabel gegenereerd en up-to-date is
    ensureParseTable(grammarFile, tableFile);
    vector<string> queries = {
        // === 1. BASIS FUNCTIONALITEIT & COMPLEXE LOGICA (Moet Parsen) ===

        // Q1: SAFE SELECT met complexe CASE WHEN (Controle op basis-parsing)
        "SELECT id, CASE WHEN LENGTH(username) > 5 THEN 'LONG' ELSE 'SHORT' END AS name_type FROM users;",

        // Q2: Geneste Scalar Subquery (Correlatie & Complexiteit)
        "SELECT id, (SELECT MAX(balance) FROM accounts WHERE accounts.user_id = users.id) AS max_balance FROM users;",
        
        // Q3: UNION Exfiltratie (Controle op UNION token detectie)
        "SELECT username FROM users UNION SELECT email FROM admins;",

        // Q4: System Enumeration (Controle op System Schema & Function calls)
        "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE();",

        // === 2. KRITISCHE BEVEILIGINGSVECTOREN (Moet BLOKKEREN) ===

        // Q5: Tautologie / Boolean-Based SQLi (Controle op OR in WHERE context)
        "SELECT * FROM users WHERE user_id = 1 OR 1=1;",

        // Q6: Stacked Query (Moet hard blokkeren bij dubbele ;)
        "SELECT id FROM users; DELETE FROM accounts WHERE balance = 0;",
        
        // Q7: Time-Based Blind SQLi (Controleert op T_SLEEP keyword, harde blokkade)
        "SELECT id FROM users WHERE EXISTS (SELECT 1 FROM accounts WHERE user_id=users.id AND balance > IF(1=1, SLEEP(3), 0));",

        // Q8: DDL Attempt (Test RBAC/DDL keyword detectie voor niet-Admin)
        "ALTER TABLE users ADD COLUMN temp_id INT;",

        "SELECT id INTO 0x4D795461626C65 FROM accounts;",
    };

    cout << "\n=== STARTING FINAL SECURITY & ACCESS CONTROL TESTS ===\n";
    // CLIENT (Alleen Lezen)
    runCheck(tableFile, queries, ROLE_CLIENT);

    // EMPLOYEE (Lezen + Schrijven)
    runCheck(tableFile, queries, ROLE_EMPLOYEE);

    // ADMIN (Alles)
    runCheck(tableFile, queries, ROLE_ADMIN);

    return 0;
}