#include "validator.h"
#include "common.h"

int main() {
    const string grammarFile = "CFG.json";
    const string tableFile = "parsetable.json";
    
    ensureParseTable(grammarFile, tableFile);

    vector<string> queries = {
        // --- DEEL 1: COMPLEXE SYNTAX (De Parser Test) ---
        // 1. Een zware query met JOIN, Aliases en WHERE logica.
        // DOEL: Laten zien dat je CFG robuust is.
        "SELECT u.name, o.date FROM users JOIN orders ON u.id = o.user_id WHERE o.total > 100 AND (u.status = 'VIP' OR u.status = 'NEW');",

        // 2. Een Nested Query (Subquery).
        // DOEL: Laten zien dat je parser recursie aankan.
        "SELECT * FROM products WHERE id IN (SELECT product_id FROM top_sellers);",


        // --- DEEL 2: RBAC HANDHAVING (De Permissie Test) ---
        // 3. Een simpele DELETE. 
        // DOEL: Client mag dit niet. Employee wel.
        "DELETE FROM logs WHERE severity = 'LOW';",

        // 4. Een DDL commando (Tabel verwijderen).
        // DOEL: Alleen ADMIN mag dit. Client/Employee worden geweigerd.
        "DROP TABLE sensitive_data;",


        // --- DEEL 3: SECURITY & FIREWALL (De Hacker Test) ---
        // 5. Classic SQL Injection (Authentication Bypass).
        // DOEL: Wordt ALTIJD geblokkeerd, ongeacht de rol.
        "SELECT * FROM users WHERE username = 'admin' OR '1'='1';",

        // 6. Comment Injection (Truncation Attack).
        // DOEL: Hacker probeert de rest van de query weg te commentariëren.
        "SELECT * FROM items; -- DROP TABLE everything;",

        // 7. UNION based injection (Data Exfiltration).
        // DOEL: Hacker probeert data uit een andere tabel te stelen.
        "SELECT name FROM products UNION SELECT password FROM users;",


        // --- DEEL 4: DE 'HACKER ADMIN' (De Context Test) ---
        // 8. Een legitieme Admin actie.
        // DOEL: Admin mag CREATE gebruiken (Firewall negeert dit veilig).
        "CREATE TABLE backup_2024 (id INT, data TEXT);"
    };

    // CLIENT (Alleen Lezen)
    runCheck(tableFile, queries, ROLE_CLIENT);

    // EMPLOYEE (Lezen + Schrijven)
    runCheck(tableFile, queries, ROLE_EMPLOYEE);

    // ADMIN (Alles)
    runCheck(tableFile, queries, ROLE_ADMIN);

    return 0;
}