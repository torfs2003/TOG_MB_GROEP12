#include "User.h"

User::User(const std::string &user_name, const std::string &password, UserRole user_role)
            : userName(user_name), password(password), userRole(user_role) {
}

const std::string& User::getName() const {
    return userName;
}
const UserRole User::getRole() const {
    return userRole;
}
const std::string& User::getPassword() const {
    return password;
}


using UserStore = std::unordered_map<std::string, std::unique_ptr<User>>;

void createUsers(UserStore& users, const std::string& userFile) {
    // file zoeken
    const std::string fileName = "../" + userFile;
    std::ifstream in(fileName);
    if (!in.is_open()) {
        throw std::runtime_error("Cannot open file: " + fileName);
    }
    // file inlezen
    json j;
    in >> j;
    const auto& arr = j.at("Users");
    if (!arr.is_array()) {
        throw std::runtime_error("\"Users\" must be an array");
    }
    // accounts aanmaken
    for (const auto& it : arr) {
        const std::string name = it.at("name").get<std::string>();
        const std::string password = it.at("password").get<std::string>();
        const std::string roleStr = it.at("role").get<std::string>();
        const UserRole role = parseRole(roleStr);

        auto [pos, inserted] = users.emplace(name, nullptr);
        if (!inserted) {
            std::cerr << name << " ALREADY EXISTS\n";
            continue;
        }
        pos->second = std::make_unique<User>(name, password, role);
    }
    // als er geen user zijn, kan het programma niet beginnen.
    if (users.empty()) {
        throw std::runtime_error("No users found");
    }
}

static UserRole parseRole(const std::string& s) {
    if (s == "ROLE_ADMIN") return UserRole::ROLE_ADMIN;
    if (s == "ROLE_EMPLOYEE")  return UserRole::ROLE_EMPLOYEE;
    if (s == "ROLE_CLIENT") return UserRole::ROLE_CLIENT;
    throw std::runtime_error("Unknown role: " + s);
}

User* authenticate(const std::string& userName, const std::string& password, const UserStore& users) {
    auto it = users.find(userName);
    if (it == users.end()) return nullptr;
    if (it->second->getPassword() != password) return nullptr;
    return it->second.get();
}

