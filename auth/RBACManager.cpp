#include "RBACManager.h"

RBACManager::RBACManager() {
    loadPermissions();
}

void RBACManager::loadPermissions() {

    // READ (DQL)
    std::unordered_set<std::string> readOps = {
        "T_SELECT",
        "T_WITH",
        "T_VALUES"
    };

    // WRITE (DML)
    std::unordered_set<std::string> writeOps = {
        "T_INSERT",
        "T_UPDATE",
        "T_DELETE"
    };

    // ADMIN (DDL & System)
    std::unordered_set<std::string> adminOps = {
        "T_CREATE",
        "T_DROP",
        "T_ALTER",
        "T_TRUNCATE",
        "T_BACKUP",
        "T_PROCEDURE",
        "T_GRANT",
        "T_REVOKE"
    };

    // CLIENT: Mag alleen lezen
    permissions[ROLE_CLIENT] = readOps;

    // EMPLOYEE: Mag lezen + schrijven
    permissions[ROLE_EMPLOYEE] = readOps;
    permissions[ROLE_EMPLOYEE].insert(writeOps.begin(), writeOps.end());

    // ADMIN: Mag alles
    permissions[ROLE_ADMIN] = readOps;
    permissions[ROLE_ADMIN].insert(writeOps.begin(), writeOps.end());
    permissions[ROLE_ADMIN].insert(adminOps.begin(), adminOps.end());
}

std::string RBACManager::getRoleName(UserRole role) {
    switch(role) {
        case ROLE_CLIENT:   return "CLIENT [R--] (Select Only)";
        case ROLE_EMPLOYEE: return "EMPLOYEE [RW-] (Select, Insert, Update, Delete)";
        case ROLE_ADMIN:    return "ADMIN [RWX] (Full Control / DDL)";
        default:            return "UNKNOWN";
    }
}

// Controleert permissies op basis van het eerste commando in de query
bool RBACManager::hasPermission(UserRole role, const std::vector<Token>& tokens) {
    if (tokens.empty()) return false;

    std::string command = "";
    for(const auto& t : tokens) {
        if (t.type == "T_LPAREN") continue;

        if (t.type != "T_EOF" && t.type != "$") {
            command = t.type;
            break;
        }
    }

    // Als er geen commando gevonden is, weiger toegang
    if (command == "") return false;

    if (permissions.count(role)) {
        if (permissions[role].count(command)) {
            return true;
        }
    }

    if (role == ROLE_ADMIN) return true;

    return false;
}