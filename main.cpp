#include "common.h"
#include "utils/QueryRunner.h"
#include "auth/User.h"

int main() {
    // Definieer de grammatica en parsetable bestanden
    const string grammarFile = "CFG.json";
    const string tableFile = "parsetable.json";
    const string queryFile = "query.json";
    const string userFile = "user.json";
    std::vector<string> queries = {};
    UserStore users = {};
    createUsers(users, userFile);
    // Leest de queries in die in de file staan.
    createQueryVector(queries, queryFile);
    // Zorg ervoor dat de parse tabel gegenereerd en up-to-date is
    ensureParseTable(grammarFile, tableFile);
    // het inloggen van de user
    User* currentUser = nullptr;
    bool loggedIn = false;
    while (!loggedIn) {
        std::cout << "Enter user name: ";
        std::string userName;
        std::cin >> userName;

        std::cout << "Enter password: ";
        std::string password;
        std::cin >> password;

        currentUser = authenticate(userName, password, users);
        if (currentUser) {
            loggedIn = true;
            std::cout << "Logged in as " << currentUser->getName() << "\n";
        } else {
            std::cout << "Invalid username or password. Try again.\n";
        }
    }
    cout << "\n=== STARTING FINAL SECURITY & ACCESS CONTROL TESTS ===\n";
    // het uitvoeren van de queries, met de bijhorende user role
    runCheck(tableFile, queries, currentUser->getRole());


    // genereren van png


    for (const fs::directory_entry& entry : fs::directory_iterator("../dot")) {
        fs::path p = entry.path();

        if (p.extension() == ".dot") {
            fs::path out = p;
            out.replace_extension(".png");

            std::string cmd =
                    "/opt/local/bin/dot -Tpng \"" +
                    p.string() +
                    "\" -o \"" +
                    out.string() + "\"";

            system(cmd.c_str());
        }
    }
    return 0;
}