
#include "CFG.h"

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
    CFG cfg = CFG("DQL.json");
    cfg.toStates();
    return 0;
}
