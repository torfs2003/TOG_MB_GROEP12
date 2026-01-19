#ifndef LALR_1__PARSER_USER_H
#define LALR_1__PARSER_USER_H

#include "UserRole.h"
#include "../common.h"

class User {
private:
    std::string userName;
    std::string password;
    UserRole userRole;
public:
    User(const std::string &user_name, const std::string &password, UserRole user_role);
    const std::string& getName() const;
    const std::string& getPassword() const;
    const UserRole getRole() const;
};

// voor het inlezen van de role
static UserRole parseRole(const std::string& s);
// het toevoegen van de user
using UserStore = std::unordered_map<std::string, std::unique_ptr<User>>;
void createUsers(UserStore& users, const std::string& userFile);
// controleert of UserName en Password al bestaad.
bool userExists(const std::string& userName, const std::string& password, const std::vector<User>& users);
// kijken of de combinatie userName en password geldig is.
User* authenticate(const std::string& userName, const std::string& password, const UserStore& users);

#endif //LALR_1__PARSER_USER_H