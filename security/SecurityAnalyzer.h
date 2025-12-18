#ifndef SECURITYANALYZER_H
#define SECURITYANALYZER_H

#include "common.h"
#include "SecurityTypes.h"
#include "../lexer/Lexer.h"
#include "../auth/UserRole.h"

// Beveiligingslaag die zoekt naar SQL Injection patronen.
class SecurityAnalyzer {
private:
    std::vector<SecurityFinding> findings;
public:
    const std::vector<SecurityFinding>& getLastFindings() const { return findings; }
    bool isDangerous(SimpleLexer& lexer, std::string query, UserRole role);
};



#endif //SECURITYANALYZER_H
