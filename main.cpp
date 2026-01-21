#include "common.h"
#include "utils/QueryRunner.h"
#include "auth/User.h"
#include <cstdlib>

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
    std::cout << "\n=== GENERATING VISUALIZATIONS ===\n";

    std::string dotCommand = "dot"; 

    #ifdef _WIN32
        std::string pathStandard = "C:\\Program Files\\Graphviz\\bin\\dot.exe";
        std::string pathX86      = "C:\\Program Files (x86)\\Graphviz\\bin\\dot.exe";

        if (fs::exists(pathStandard)) {
            dotCommand = "\"" + pathStandard + "\"";
        } 
        else if (fs::exists(pathX86)) {
            dotCommand = "\"" + pathX86 + "\"";
        }
    #endif

    // 2. Controleren en uitvoeren
    if (fs::exists("../dot")) {
        int count = 0;
        for (const auto& entry : fs::directory_iterator("../dot")) {
            fs::path p = entry.path();

            if (p.extension() == ".dot") {
                fs::path out = p;
                out.replace_extension(".png");

                // Commando opbouwen
                std::string args = " -Tpng \"" + p.string() + "\" -o \"" + out.string() + "\"";
                std::string fullCmd = dotCommand + args;

                #ifdef _WIN32

                    fullCmd = "\"" + fullCmd + "\"";
                #endif

                int result = system(fullCmd.c_str());

                if (result != 0) {
                    std::cerr << " [ERROR] Failed for " << p.filename() << "\n";
                }
                count++;
            }
        }
        if (count == 0) std::cout << " [INFO] No .dot files found.\n";
    } else {
        std::cerr << "[Warning] Directory '../dot' not found.\n";
    }
    return 0;
}