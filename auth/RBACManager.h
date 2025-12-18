#ifndef RBACMANAGER_H
#define RBACMANAGER_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "UserRole.h"
#include "../core/Token.h"

// Controleert of een gebruiker (UserRole) een bepaald commando mag uitvoeren.
class RBACManager {
private:
    // De Matrix: Koppelt een Rol aan een Set van toegestane commando's
    std::unordered_map<UserRole, std::unordered_set<std::string>> permissions;
    void loadPermissions();

public:
    RBACManager();

    std::string getRoleName(UserRole role);
    bool hasPermission(UserRole role, const std::vector<Token>& tokens);
};



#endif //RBACMANAGER_H
