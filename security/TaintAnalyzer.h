#ifndef TAINTANALYZER_H
#define TAINTANALYZER_H

#include <vector>
#include "../core/AST.h"
#include "SecurityTypes.h"

class TaintAnalyzer {
public:
    void analyze(ASTNode* root);
    [[nodiscard]] const std::vector<SecurityFinding>& getFindings() const;
    void clearFindings();
private:
    std::vector<SecurityFinding> findings;
    void markTaintSources(ASTNode* node);
    void propagateTaint(ASTNode* node);
    void checkTaintSinks(ASTNode* node);
};

#endif //TAINTANALYZER_H
