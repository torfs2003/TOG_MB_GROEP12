#ifndef AST_H
#define AST_H
#include <string>
#include <utility>
#include <vector>
#include <iostream>
#include "Token.h"

struct ASTNode {
    std::string type;
    std::string value;
    bool isTainted = false;
    std::vector<ASTNode*> children;

    explicit ASTNode(const Token& token)
        : type(token.type), value(token.value) {}

    explicit ASTNode(std::string  t, std::string  val, const std::vector<ASTNode*>& ch = {})
        : type(std::move(t)), value(std::move(val)), children(ch) {}

    void print(int indent = 0) const {
        std::string pad(indent * 2, ' ');
        std::cout << pad << type;
        if (!value.empty()) std::cout << " (" << value << ")";
        if (isTainted) std::cout << " [TAINTED]";
        std::cout << "\n";
        for (auto* child : children) {
            if (child) child->print(indent + 1);
        }
    }
};

#endif //AST_H
