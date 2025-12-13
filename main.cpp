#include "validator.h"
#include "LALR.h"
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>

namespace fs = std::filesystem;

int main() {
    const std::string grammarFile = "CFG.json";
    const std::string tableFile = "parsetable.json";
    bool needToGenerate = true;

    // Check if we need to regenerate the parse table
    if (fs::exists(tableFile) && fs::exists(grammarFile)) {
        auto grammarTime = fs::last_write_time(grammarFile);
        auto tableTime = fs::last_write_time(tableFile);

        if (tableTime > grammarTime) {
            std::cout << "Parse table is up to date. Skipping generation.\n";
            needToGenerate = false;
        } else {
            std::cout << "Grammar file has changed. Regenerating parse table...\n";
        }
    } else {
        std::cout << "Parse table not found. Generating...\n";
    }

    if (needToGenerate) {
        CFG cfg(grammarFile);
        cfg.toStates();      
        cfg.saveTableToJSON(tableFile);
    }
    
    SimpleLexer lexer;
    LALRParser parser(tableFile);

    std::vector<std::string> queries = {
        // ============================================================
        // 12. ERROR: INSERT missing 'VALUES' keyword
        // ============================================================
        // Expectation: Error at '(', expected 'VALUES' or 'SELECT'.
        "INSERT INTO users (id, name) "
        "(1, 'Alice');", 

        // ============================================================
        // 13. ERROR: DELETE with '*' (Invalid Syntax)
        // ============================================================
        // Expectation: Error at '*', DELETE usually implies * (DELETE FROM...).
        // If your grammar supports 'DELETE *', this might pass, but ANSI is 'DELETE FROM'.
        "DELETE * FROM users WHERE id = 10;",

        // ============================================================
        // 14. ERROR: 'IS' operator syntax
        // ============================================================
        // Expectation: Error at '=', expected 'NULL' or 'NOT'. 
        // (You cannot say 'IS = NULL')
        "SELECT * FROM products WHERE category IS = NULL;",

        // ============================================================
        // 15. ERROR: Conflicting ORDER BY direction
        // ============================================================
        // Expectation: Error at 'DESC', unexpected token after 'ASC'.
        "SELECT name FROM students ORDER BY grade ASC DESC;",

        // ============================================================
        // 16. ERROR: Missing Constraint Keyword (PRIMARY KEY)
        // ============================================================
        // Expectation: Error at ')', expected 'KEY'.
        "CREATE TABLE orders ("
        "    id INT PRIMARY, "  // <--- Missing 'KEY'
        "    total DECIMAL"
        ");",

        // ============================================================
        // 17. ERROR: Duplicate Keyword (DISTINCT)
        // ============================================================
        // Expectation: Error at second 'DISTINCT'.
        "SELECT DISTINCT DISTINCT name FROM users;",

        // ============================================================
        // 18. ERROR: Dangling Logical Operator
        // ============================================================
        // Expectation: Error at ';', expected expression.
        "SELECT * FROM data WHERE active = 1 AND;",

        // ============================================================
        // 19. ERROR: Missing Alias after AS
        // ============================================================
        // Expectation: Error at 'FROM', expected identifier.
        "SELECT COUNT(*) AS FROM data;", 

        // ============================================================
        // 20. ERROR: Empty Function Arguments (if grammar requires args)
        // ============================================================
        // Expectation: Error at ')', MAX usually requires arguments.
        "SELECT MAX() FROM numbers;" 
    };
    printErrors(lexer, parser, queries);
    return 0;
}