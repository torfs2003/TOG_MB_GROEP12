#ifndef QUERYRUNNER_H
#define QUERYRUNNER_H
#include <string>
#include <vector>
#include "../auth/UserRole.h"

void ensureParseTable(const std::string& grammarFile, const std::string& tableFile);
void runCheck(const std::string& tableFile, const std::vector<std::string>& queries, UserRole role);

#endif //QUERYRUNNER_H
