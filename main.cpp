#include "validator.h"
#include "common.h"

int main() {
    // Definieer de grammatica en parsetable bestanden
    const string grammarFile = "CFG.json";
    const string tableFile = "parsetable.json";
    
    // Zorg ervoor dat de parse tabel gegenereerd en up-to-date is
    ensureParseTable(grammarFile, tableFile);
    vector<string> queries = {
        // =========================================================
        // GROUP 7: THE TAUTOLOGY TRAPS (Code 1 vs Code 2 Showdown)
        // =========================================================

        // 19. The "Legitimate Employee" Test (False Positive check)
        // SCENARIO: Een employee wil gewoon filteren op twee statussen. Dit is ECHTE, veilige SQL.
        // CODE 1: Ziet 'OR' en BLOCKT genadeloos (tenzij Admin). -> FALSE POSITIVE
        // CODE 2: Inspecteert tokens, ziet status='open' OR status='new'. Dit matcht GEEN tautologie regels.
        //         Zou toegestaan moeten worden (of slechts een lichte warning geven), maar geen Hard Block.
        R"(SELECT * FROM orders WHERE status = 'open' OR status = 'new';)",

        // 20. The "Classic Admin Backdoor" (Insider Threat check)
        // SCENARIO: Een gecompromitteerde Admin account probeert data te dumpen.
        // CODE 1: Ziet 'Admin' rol -> ALLOWED. (Groot beveiligingsrisico!)
        // CODE 2: Ziet 'OR 1=1'. Matcht de "OR literal=literal" regel -> CRITICAL BLOCK.
        R"(SELECT * FROM sensitive_data WHERE id = 1 OR 1=1;)",

        // 21. The "Type Mismatch" Bypass (Code 2 Blind Spot check)
        // SCENARIO: SQL engines zijn vergevingsgezind (1 = '1' is vaak true), maar je C++ code checkt (t1 == t3).
        // CODE 2 LOGICA: if (t1 == t3 && v1 == v3)...
        //         Hier is t1=INT(1) en t3=STRING('1'). De types matchen niet.
        // TEST: Glipt deze "Tautology" check erdoorheen in Code 2?
        R"(SELECT * FROM users WHERE id = 1 OR 1 = '1';)",

        // 22. The "Math Expression" Bypass (Lookahead limitation check)
        // SCENARIO: Je code kijkt naar token [i+3].
        //         OR 10 = 5 + 5
        //         [i+1]=10, [i+2]=IsGelijk, [i+3]=5.
        // CODE 2: Vergelijkt "10" met "5". Ziet geen match. Ziet geen "AlwaysTrue".
        // TEST: Snapt je firewall dat 5+5 ook 10 is, of kijkt hij niet diep genoeg? (Waarschijnlijk bypass).
        R"(SELECT * FROM wallet WHERE id = 1 OR 10 = 5 + 5;)",

        // 23. The "Hex/Bitwise" Tautology (Advanced check)
        // SCENARIO: Gebruik van niet-standaard literals om 'True' te forceren.
        // CODE 2: Heeft een specifieke check voor "OR TRUE" en "OR Non-Zero INT".
        //         Maar herkent hij hexadecimaal 0x1 als een non-zero int?
        // TEST: Wordt 0x1 geparst als T_INT of T_HEX? Als het geen T_INT is, faalt je check.
        R"(SELECT * FROM secrets WHERE id = 1 OR 0x1;)",

        // 24. The "Always False" sanity check
        // SCENARIO: OR 1=0 is een tautologie patroon (literal=literal), maar het resultaat is FALSE.
        // CODE 2: Je code checkt (v1 == v3). 1 != 0. Dus geen match.
        //         Daarna checkt hij 'Always True' logica (<, >).
        //         1=0 is niet 'Always True'.
        // TEST: Dit zou GEEN critical block moeten triggeren in Code 2, want het is geen aanval (het levert niks op).
        R"(SELECT * FROM products WHERE id = 1 OR 1 = 0;)",

        // 25. The "Capitalization" trick
        // SCENARIO: Je code doet `transform(..., ::toupper)` voor 'TRUE', maar doet hij dat ook voor de query 'Or'?
        // TEST: Als je parser case-sensitive is op keywords, werkt dit misschien niet.
        //       Als je code checkt op "T_OR", zou de lexer dit al opgelost moeten hebben.
        R"(SELECT * FROM users WHERE id=1 oR 1=1;)"
        // =========================================================
        // GROUP 8: THE SILENT KILLERS & COMPLEXITY STRESS TEST
        // =========================================================

        // 26. The "Date vs Math" Confusion
        // SCENARIO: Datums zonder quotes zijn rekensommen in SQL.
        // TEST: Parsed je dit als een datum string, of als (2023 - 12 - 01)?
        //       Als je firewall hierop crashed of T_UNKNOWN geeft, is je lexer te strikt.
        R"(SELECT * FROM log WHERE event_date > '2023-12-31' AND event_time < '23:59:59';)",

        // 27. The "Comment Obfuscation" Attack
        // SCENARIO: Hackers vervangen spaties door comments /**/ om firewalls te omzeilen die simpel op strings zoeken.
        // CODE 1/2: Als je lexer comments niet goed verwijdert *voordat* de firewall checkt, ziet hij "SELECT/**/id".
        // TEST: Wordt dit "SELECT id" (Valid) of "SELECT/**/id" (Invalid Token)?
        R"(SELECT/**/id/**/FROM/**/users/**/WHERE/**/1=1;)",

        // 28. The "Union-Select" Data Theft
        // SCENARIO: De gevaarlijkste SQLi na 1=1. Plakt resultaten van de 'passwords' tabel achter de 'products' tabel.
        // TEST: Detecteert je firewall de 'UNION' keyword? En checkt hij rechten opnieuw voor het tweede deel?
        //       (Admin mag dit, Employee/Client absoluut niet).
        R"(SELECT name, description FROM products WHERE id=1 UNION SELECT username, password FROM users;)",

        // 29. The "Timestamp Function" Call
        // SCENARIO: Functies zoals NOW(), CURRENT_TIMESTAMP, DATE().
        // TEST: Snapt je parser functies zonder argumenten (NOW()) vs met argumenten (DATE('...'))?
        R"(INSERT INTO access_logs (user_id, login_time) VALUES (101, NOW());)",

        // 30. The "Polymorphic" Tautology (CAST injection)
        // SCENARIO: Je vorige firewall miste 1 = '1' (Type Mismatch).
        //           Hackers gebruiken CAST om types gelijk te trekken zodat de database het snapt, maar de firewall niet.
        // TEST: Ziet je firewall dat CAST(1 AS VARCHAR) hetzelfde is als '1'? (Waarschijnlijk niet -> Blind Spot).
        R"(SELECT * FROM data WHERE id=1 OR CAST(1 AS VARCHAR) = '1';)",

        // 31. The "Nested Complexity" (Stack Overflow check)
        // SCENARIO: Extreem diepe nesting.
        // TEST: Crashed je parser (stack overflow) of handelt hij dit netjes af?
        R"(SELECT * FROM (SELECT * FROM (SELECT * FROM (SELECT 1 AS a) t1) t2) t3;)",

        // 32. The "Silent Arithmetic" Injection
        // SCENARIO: In plaats van OR 1=1, gebruiken hackers wiskunde die altijd waar is maar geen '=' teken bevat.
        //           Bijv: OR 5 (in SQL is non-zero true).
        // CODE 2: Je hebt een check voor "OR non-zero". Werkt die ook met negatieve getallen?
        R"(SELECT * FROM debts WHERE amount > 0 OR -1;)",

        // 33. The "Mixed Case Keyword" Hell
        // SCENARIO: SeLeCt * fRoM...
        // TEST: Is je tokenizer echt case-insensitive voor keywords?
        R"(SeLeCt * FrOm users WhErE id Is NoT NulL;)"
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