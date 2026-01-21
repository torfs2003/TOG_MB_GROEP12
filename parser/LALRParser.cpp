#include "LALRParser.h"

#include "../common.h"

LALRParser::LALRParser(std::string filename) {
    std::ifstream f(filename);
    if (!f.is_open()) {
        std::cerr << "Error: Could not open " << filename << std::endl;
        exit(1);
    }
    json j;
    f >> j;

    // Laad de Action Table
    for (auto& [stateStr, actions] : j["action_table"].items()) {
        int state = std::stoi(stateStr);
        for (auto& [sym, act] : actions.items()) {
            std::string type = act["type"];

            if (type == "SHIFT") {
                actionTable[state][sym] = {ParserAction::SHIFT, (int)act["state"], "", 0};
            } else if (type == "REDUCE") {
                actionTable[state][sym] = {ParserAction::REDUCE, 0, act["lhs"], (int)act["rhs"].size()};
            } else if (type == "ACCEPT") {
                actionTable[state][sym] = {ParserAction::ACCEPT, 0, "", 0};
            }
        }
    }

    // Laad de Goto Table
    for (auto& [stateStr, gotos] : j["goto_table"].items()) {
        int state = std::stoi(stateStr);
        for (auto& [nonTerm, nextState] : gotos.items()) {
            gotoTable[state][nonTerm] = (int)nextState;
        }
    }
}

ASTNode* LALRParser::parse(const std::vector<Token>& tokens) {
    std::stack<int> stateStack;
    std::stack<ASTNode*> valueStack;
    stateStack.push(0);

    int tokenIdx = 0;
    bool globalError = false;
    bool currentQueryError = false;
    bool recoveryMode = false;
    int queryCount = 1;


    while (tokenIdx < tokens.size()) {
        int currentState = stateStack.top();
        Token currentToken = tokens[tokenIdx];
        std::string sym = currentToken.type;

        // Als er geen actie is voor dit symbool in de huidige state: Error
        if (actionTable[currentState].find(sym) == actionTable[currentState].end()) {

            if (currentState == 0 && (sym == "T_EOF" || sym == "$")) {
                return globalError ? nullptr : (valueStack.empty() ? nullptr : valueStack.top());
            }
            if (!recoveryMode) {
                std::cout << "\n    --> [Syntax Error] Unexpected '" << currentToken.value
                     << "' (" << sym << ") in State " << currentState << std::endl;

                currentQueryError = true;
                globalError = true;
                recoveryMode = true;
            }

            // Probeer te herstellen bij een puntkomma (;)
            if (sym == "T_PCOMMA") {

                while(!stateStack.empty()) stateStack.pop();
                stateStack.push(0);

                tokenIdx++;
                recoveryMode = false;
                currentQueryError = false;
                queryCount++;
                continue;
            }
            else if (sym == "T_EOF" || sym == "$") {
                 return nullptr;
            }
            else {
                tokenIdx++;
                continue;
            }
        }

        ParserAction act = actionTable[currentState][sym];

        if (act.type == ParserAction::SHIFT) {
            stateStack.push(act.state);
            valueStack.push(new ASTNode(currentToken));
            tokenIdx++;
        }
        else if (act.type == ParserAction::REDUCE) {
            std::vector<ASTNode*> children;
            for (int i = 0; i < act.rhsSize; i++) {
                if(!valueStack.empty()) {
                    children.push_back(valueStack.top());
                    valueStack.pop();
                }
                if (!stateStack.empty()) stateStack.pop();
            }
            std::reverse(children.begin(), children.end());
            if (stateStack.empty()) stateStack.push(0);

            // filter tokens die niet belangrijk zijn voor de AST
            std::vector<ASTNode*> filtered;
            for (auto* child : children) {
                if (!child) continue;
                std::string t = child->type;
                if (t == "T_COMMA" || t == "T_PCOMMA" || t == "T_LPAREN" ||
                    t == "T_RPAREN" || t == "T_EOF") continue;
                filtered.push_back(child);
            }

            if (filtered.empty() && act.lhs.substr(0, 4) == "opt_") {
                // skip optionele nodes
            } else if (filtered.size() == 1) {
                valueStack.push(filtered[0]); // als er maar 1 child is vervang de node met die child
            } else {
                valueStack.push(new ASTNode(act.lhs, "", filtered));
            }

            int topState = stateStack.top();
            if (gotoTable[topState].find(act.lhs) == gotoTable[topState].end()) {
                return nullptr;
            }
            stateStack.push(gotoTable[topState][act.lhs]);
        }
        else if (act.type == ParserAction::ACCEPT) {
            if (globalError) return nullptr;
            return valueStack.empty() ? nullptr : valueStack.top();
        }
    }
    return nullptr;
}