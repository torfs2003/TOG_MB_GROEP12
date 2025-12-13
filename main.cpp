#include "validator.h"
#include "LALR.h"

namespace fs = std::filesystem;
int main() {
    const std::string grammarFile = "CFG.json";
    const std::string tableFile = "parsetable.json";
    bool needToGenerate = true;

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
    LALRParser parser("parsetable.json");

    vector<string> queries = {
        // ============================================================
        // 1. COMPLEX SELECTS: Logic, Arithmetic & Bitwise
        // ============================================================
        
        "SELECT "
        "    e.id, "
        "    (e.base_salary * 1.05) + (e.bonus / 2) - 100 AS net_pay, "
        "    e.first_name || ' ' || e.last_name || ' (' || e.role || ')' AS display_name, "
        "    (u.flags & 15) | 1 AS permission_mask, "
        "    -(e.score + 5) AS penalty_score "
        "FROM employees e "
        "JOIN users u ON e.user_id = u.id "
        "WHERE (e.status = 'ACTIVE' OR e.status = 'PENDING') "
        "  AND (u.flags ^ 255) > 0;",

        "SELECT "
        "    product_name, "
        "    price * (CASE "
        "        WHEN category = 'Electronics' THEN "
        "            CASE WHEN stock > 50 THEN 0.9 ELSE 1.0 END "
        "        WHEN category = 'Clothing' THEN 0.8 "
        "        ELSE 1.0 "
        "    END) AS final_price "
        "FROM products "
        "WHERE price IS NOT NULL;",

        "SELECT id FROM logs "
        "WHERE CAST(severity AS INT) > 3 "
        "  AND CONVERT(DATE, timestamp, 101) = '2023-12-25';",

        // ============================================================
        // 2. ADVANCED FILTERING: Subqueries & Quantifiers
        // ============================================================

        "SELECT c.name "
        "FROM customers c "
        "WHERE c.country IN ('USA', 'Canada', 'UK') "
        "  AND EXISTS ("
        "      SELECT 1 FROM orders o "
        "      WHERE o.customer_id = c.id "
        "        AND o.amount > 500 "
        "        AND o.date > '2023-01-01'"
        "  );",

        "SELECT name, salary "
        "FROM employees "
        "WHERE salary > ALL (SELECT AVG(salary) FROM employees GROUP BY department_id) "
        "   OR bonus > ANY (SELECT bonus FROM executives);",

        "SELECT sku FROM inventory "
        "WHERE (sku LIKE 'A%' OR sku LIKE '%-X') "
        "  AND stock BETWEEN 10 AND 100;",

        // ============================================================
        // 3. TABLE SOURCES: Joins & Derived Tables
        // ============================================================

        "SELECT t1.col1, t2.col2, t3.col3 "
        "FROM table1 t1 "
        "INNER JOIN table2 t2 ON t1.id = t2.t1_id "
        "LEFT OUTER JOIN table3 t3 ON t2.id = t3.t2_id "
        "CROSS JOIN config_settings cs "
        "WHERE t1.active = 1;",

        "SELECT dt.dept_name, dt.avg_sal "
        "FROM ("
        "    SELECT d.name AS dept_name, AVG(e.salary) AS avg_sal "
        "    FROM departments d "
        "    JOIN employees e ON d.id = e.dept_id "
        "    GROUP BY d.name"
        ") AS dt "
        "WHERE dt.avg_sal > 50000;",

        "SELECT * "
        "FROM students "
        "NATURAL JOIN grades "
        "WHERE score > 90;",

        // ============================================================
        // 4. AGGREGATION & WINDOWING
        // ============================================================

        "SELECT "
        "    category, "
        "    COUNT(DISTINCT product_id) AS unique_items, "
        "    SUM(quantity * price) AS revenue "
        "FROM sales "
        "GROUP BY category "
        "HAVING SUM(quantity * price) > 10000 "
        "   AND COUNT(*) > 50 "
        "ORDER BY revenue DESC;",

        "SELECT "
        "    name, "
        "    dept, "
        "    salary, "
        "    ROW_NUMBER() OVER (PARTITION BY dept ORDER BY salary DESC) AS rn, "
        "    RANK() OVER (PARTITION BY dept ORDER BY salary DESC) AS rnk, "
        "    AVG(salary) OVER (PARTITION BY dept) AS avg_dept_pay, "
        "    SUM(salary) OVER (ORDER BY hired_date ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS running_total "
        "FROM staff;",

        // ============================================================
        // 5. SET OPERATIONS & CTEs
        // ============================================================

        "SELECT id FROM local_users "
        "UNION ALL "
        "SELECT id FROM remote_users "
        "EXCEPT "
        "SELECT id FROM blacklist "
        "INTERSECT "
        "SELECT id FROM active_sessions;",

        "WITH sales_stats AS ("
        "    SELECT rep_id, SUM(amount) AS total FROM sales GROUP BY rep_id"
        "), "
        "top_performers AS ("
        "    SELECT rep_id FROM sales_stats WHERE total > 100000"
        ") "
        "SELECT e.name "
        "FROM employees e "
        "JOIN top_performers tp ON e.id = tp.rep_id;",

        // ============================================================
        // 6. DATA MODIFICATION (DML)
        // ============================================================

        "INSERT INTO archive_logs (log_id, msg, archived_at) "
        "SELECT id, message, '2024-01-01' "
        "FROM logs "
        "WHERE status = 'RESOLVED';",

        "UPDATE products "
        "SET price = price * 1.1, "
        "    updated_at = DEFAULT "
        "WHERE category_id IN (SELECT id FROM categories WHERE region = 'EU');",

        "DELETE TOP 100 FROM sessions "
        "WHERE last_active < '2023-01-01' "
        "  AND user_id NOT IN (SELECT id FROM vip_users);",

        // ============================================================
        // 7. DDL: CREATE
        // ============================================================

        "CREATE TABLE heavy_duty_table ("
        "    id INT PRIMARY KEY AUTOINCREMENT, "
        "    uuid VARCHAR(36) NOT NULL UNIQUE, "
        "    parent_id INT REFERENCES heavy_duty_table(id), "
        "    status INT DEFAULT 0, "
        "    meta_data JSON, "
        "    score DECIMAL(10,2) CHECK (score >= 0.0 AND score <= 100.0)"
        ");",

        "CREATE VIEW quarterly_report AS "
        "SELECT "
        "    region, "
        "    QUARTER(date) AS qtr, "
        "    SUM(sales) AS total "
        "FROM transaction_data "
        "GROUP BY region, QUARTER(date);",

        "CREATE PROCEDURE monthly_maintenance AS "
        "BEGIN "
        "DELETE FROM temp_logs WHERE created_at < '2024-01-01'; "
        "UPDATE system_stats SET last_run = DEFAULT; "
        "INSERT INTO job_history (job_name, status) VALUES ('maintenance', 'success') "
        "END;", 

        "ALTER TABLE users "
        "ADD COLUMN middle_name VARCHAR(50) DROP COLUMN nickname ADD CONSTRAINT uq_email UNIQUE ALTER COLUMN status TINYINT;",

        "DROP TABLE IF EXISTS old_backup;", 
        "DROP VIEW sales_summary;",
        "DROP INDEX idx_names;",

        // ============================================================
        // 9. EXTENSIONS & MISC
        // ============================================================

        "SELECT id, name, salary "
        "INTO backup_employees_2024 "
        "FROM employees "
        "WHERE active = 1;",

        "TRUNCATE TABLE session_cache;",

        "SELECT DISTINCT TOP 5 city "
        "FROM addresses "
        "ORDER BY city ASC;",

        "SELECT * FROM table1;",

        "SELECT * FROM math_test "
        "WHERE ((a + b) * (c - d)) / (e + (f * g)) > 100;"
    };

    cout << "Loading Parse Table... Done.\n";
    cout << "Running 5 Validation Queries...\n";
    cout << "================================\n";

    for (int i = 0; i < queries.size(); i++) {
        cout << "Query " << (i + 1) << ": ";
        
        vector<Token> tokens = lexer.tokenize(queries[i]);
        bool result = parser.parse(tokens);

        if (result) {
            cout << "\033[1;32m[ACCEPTED]\033[0m" << endl;
        } else {
            cout << "\033[1;31m[REJECTED]\033[0m" << endl;
        }
    }

    return 0;
}

