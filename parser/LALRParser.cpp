#include "LALRParser.h"

#include <fstream>
#include <iostream>
#include <stack>
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

bool LALRParser::parse(std::vector<Token>& tokens) {
    std::stack<int> stateStack;
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
                return !globalError;
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
                 return false;
            }
            else {
                tokenIdx++;
                continue;
            }
        }

        ParserAction act = actionTable[currentState][sym];

        if (act.type == ParserAction::SHIFT) {
            stateStack.push(act.state);
            tokenIdx++;

            // Bij een puntkomma is de query afgerond
            if (sym == "T_PCOMMA") {

                while(!stateStack.empty()) stateStack.pop();
                stateStack.push(0);

                recoveryMode = false;
                currentQueryError = false;
                queryCount++;

            }
        }
        else if (act.type == ParserAction::REDUCE) {
            for (int i = 0; i < act.rhsSize; i++) {
                if (!stateStack.empty()) stateStack.pop();
            }
            if (stateStack.empty()) stateStack.push(0);

            int topState = stateStack.top();
            if (gotoTable[topState].find(act.lhs) == gotoTable[topState].end()) {
                return false;
            }
            stateStack.push(gotoTable[topState][act.lhs]);
        }
        else if (act.type == ParserAction::ACCEPT) {
            return !globalError;
        }
    }
    return !globalError;
}