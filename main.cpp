#include <iostream>
#include <fstream>
#include <sstream>
#include "SQLGuard.h"

using namespace std;

string readQueryFromFile(string filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cerr << "Error: Kan bestand '" << filename << "' niet openen." << endl;
        return "";
    }
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    SQLGuard tool;

    cout << "=== TEST 1: De Basis (Strings, Integers, Comma's) ===" << endl;
    // Test: Strings met quotes, Integers, en basis operatoren (=)
    tool.debugLexer("SELECT name, age FROM users WHERE id = 100 AND role = 'admin'");

    cout << "\n=== TEST 2: Complexe Operatoren (Lookahead Logic) ===" << endl;
    // Test: <=, >=, <>, !=, <, >
    // Als dit werkt, werkt je switch-case logica perfect
    tool.debugLexer("SELECT * FROM products WHERE price <= 50.5 AND stock >= 10 AND type <> 'trash' AND code != 99");

    cout << "\n=== TEST 3: Logica, Null Checks & Aliassen ===" << endl;
    // Test: IS, NOT, NULL, OR, AS, EXISTS
    tool.debugLexer("SELECT p.name AS title FROM products p WHERE description IS NOT NULL OR EXISTS (SELECT 1)");

    cout << "\n=== TEST 4: Aggregaties & Groeperen ===" << endl;
    // Test: COUNT, SUM, AVG, MIN, MAX, GROUP BY, HAVING, ORDER BY
    tool.debugLexer("SELECT category, COUNT(*), SUM(price), AVG(rating), MIN(x), MAX(y) FROM data GROUP BY category HAVING count > 5 ORDER BY price");

    cout << "\n=== TEST 5: DDL Commando's (Data Definition) ===" << endl;
    // Test: CREATE, DROP, ALTER, TABLE
    tool.debugLexer("CREATE TABLE new_users; DROP TABLE old_users; ALTER TABLE products");

    cout << "\n=== TEST 6: Foutafhandeling (Edge Cases) ===" << endl;
    // Test 1: Rare whitespace (tabs, newlines) -> Regelnummers moeten kloppen
    tool.debugLexer("SELECT *\nFROM\n\tusers");
    
    // Test 2: Unclosed String -> Moet Lexer Error geven
    tool.debugLexer("SELECT 'Dit is een string die nooit eindigt");
    string fileQuery = readQueryFromFile("query.txt");

    if (fileQuery.empty()) {
        cout << "Let op: Het bestand is leeg." << endl;
    } else {
        cout << "Bestand gevonden. Inhoud: " << fileQuery.substr(0, 20) << "..." << endl;
        tool.analyze(fileQuery);
    }
    return 0;
}