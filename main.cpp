#include "validator.h"
#include "common.h"

int main() {
    // Definieer de grammatica en parsetable bestanden
    const string grammarFile = "CFG.json";
    const string tableFile = "parsetable.json";
    
    // Zorg ervoor dat de parse tabel gegenereerd en up-to-date is
    ensureParseTable(grammarFile, tableFile);

    vector<string> queries = {
        "CREATE TABLE logs_prod (id INT);", 

        "SELECT COUNT(id) FROM \"Users\" WHERE department = 'IT' AND team_name = 'Alpha';",

        "SELECT name FROM products WHERE id = 1 UNION SELECT user, password FROM information_schema.tables;", 

        "SELECT 1; TRUNCATE TABLE session_data; -- comment", 

        "SELECT * FROM users WHERE id = 1 OR 1=1 AND (SELECT SLEEP(5));",
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