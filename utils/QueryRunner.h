#ifndef QUERYRUNNER_H
#define QUERYRUNNER_H
#include <string>
#include <vector>
#include "../auth/UserRole.h"

void ensureParseTable(const std::string& grammarFile, const std::string& tableFile);
void runCheck(const std::string& tableFile, const std::vector<std::string>& queries, UserRole role);
void createQueryVector(std::vector<std::string>& queries, const std::string& queryFile);

#endif //QUERYRUNNER_H
