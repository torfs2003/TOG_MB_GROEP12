#include "TaintAnalyzer.h"
#include <iostream>

void TaintAnalyzer::markTaintSources(ASTNode* node) {
    if (!node) return;

    // markeer user input als tainted
    if (node->type == "T_PLACEHOLDER") {
        node->isTainted = true;
    }

    // markeer children van node als tainted
    for (ASTNode* child : node->children) {
        markTaintSources(child);
    }
}

void TaintAnalyzer::propagateTaint(ASTNode* node) {
    if (!node) return;
    
    // markeer children van node als tainted
    for (ASTNode* child : node->children) {
        propagateTaint(child);
    }
    
    // als een child van de node tainted is dan is de node zelf tainted
    for (ASTNode* child : node->children) {
        if (child && child->isTainted) {
            node->isTainted = true;
            return;
        }
    }
}

// sink = gevaarlijke locatie waar tainted data gebruikt wordt
void TaintAnalyzer::checkTaintSinks(ASTNode* node) {
    if (!node) return;
    
    // check voor tainted data in sensitieve node types, rapporteer enkel hoge-niveau nodes om duplicates te vermijden
    if (node->isTainted) {
        if (node->type == "opt_where") {
            findings.push_back({
                SEV_HIGH_RISK,
                "Tainted data (user input) detected in WHERE clause. Potential SQL injection risk."
            });
        }
        
        else if (node->type == "join_condition") {
            findings.push_back({
                SEV_HIGH_RISK,
                "Tainted data (user input) detected in JOIN ON condition. Potential SQL injection risk."
            });
        }
        
        else if (node->type == "opt_having") {
            findings.push_back({
                SEV_HIGH_RISK,
                "Tainted data (user input) detected in HAVING clause. Potential SQL injection risk."
            });
        }
        
        else if (node->type == "value_list" || node->type == "row_value") {
            findings.push_back({
                SEV_HIGH_RISK,
                "Tainted data (user input) detected in INSERT VALUES. Potential SQL injection risk."
            });
        }
        
        else if (node->type == "assignment_list") {
            findings.push_back({
                SEV_HIGH_RISK,
                "Tainted data (user input) detected in UPDATE SET. Potential SQL injection risk."
            });
        }
        
        else if (node->type == "opt_order" || node->type == "order_list") {
            findings.push_back({
                SEV_MEDIUM_PRIVILEGE,
                "Tainted data in ORDER BY clause. Potential blind SQL injection risk."
            });
        }
        
        if (node->type == "function_call") {
            if (!node->children.empty()) {
                ASTNode* functionName = node->children[0];
                if (functionName && (functionName->value == "SLEEP" || functionName->value == "BENCHMARK" || 
                                 functionName->type == "T_SLEEP" || functionName->type == "T_BENCHMARK")) {
                    findings.push_back({
                        SEV_CRITICAL_HARD_BLOCK,
                        "Tainted data used in time-based function (" + functionName->value + "). Critical security risk."
                    });
                }
            }
        }
        
        if (node->type == "select_statement") {
            for (ASTNode* child : node->children) {
                if (child && (child->type == "T_UNION" || child->value == "UNION")) {
                    findings.push_back({
                        SEV_HIGH_RISK,
                        "Tainted data in UNION operation. Potential data exfiltration risk."
                    });
                    return;
                }
            }
        }
    }
    
    // check children met recursie
    for (ASTNode* child : node->children) {
        checkTaintSinks(child);
    }
}

void TaintAnalyzer::analyze(ASTNode* root) {
    if (!root) return;
    
    findings.clear();

    markTaintSources(root);

    propagateTaint(root);

    checkTaintSinks(root);

    if (!findings.empty()) {
        std::cout << "    [Taint Analysis] Found " << findings.size() << " taint-related security issue(s):" << std::endl;
        for (const auto& finding : findings) {
            std::cout << "  --> \033[1;33m[TAINT]\033[0m " << finding.message << std::endl;
        }
    } else {
        std::cout << "    [Taint Analysis] No taint flow issues detected." << std::endl;
    }
}

const std::vector<SecurityFinding> & TaintAnalyzer::getFindings() const {
    return findings;
}

void TaintAnalyzer::clearFindings() {
    findings.clear();
}
