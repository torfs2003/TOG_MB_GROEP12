//
// Created by ruben on 2/12/2025.
//

#ifndef LALR_1__PARSER_CFG_H
#define LALR_1__PARSER_CFG_H

#include <iostream>
#include <vector>
#include <fstream>
#include <map>
#include <random>
#include <set>
#include <variant>

struct Production {
    std::string head;
    std::vector<std::string> body;
    Production() = default;
    Production(std::string h, std::vector<std::string> b)
            : head(std::move(h)), body(std::move(b)) {}
    bool operator<(const Production& other) const {
        if (head != other.head)
            return head < other.head;
        return body < other.body;
    }
};

struct StateProduction {
    std::string head;
    std::vector<std::string> body;
    std::set<std::string> lookahead;

    StateProduction(const std::string &head, const std::vector<std::string> &body,
        const std::set<std::string> &lookahead)
        : head(head),
          body(body),
          lookahead(lookahead) {
    }
    bool operator<(const StateProduction& other) const {
        return std::tie(head, body) < std::tie(other.head, other.body);
    }
    bool operator==(const StateProduction& other) const {
        return head == other.head && body == other.body && lookahead == other.lookahead;
    }
    bool sameBody(const StateProduction& other) const {
        return std::tie(head, body) == std::tie(other.head, other.body);
    }
};
using State = std::set<StateProduction>;
struct namedState {
    std::string name;
    State state;

    namedState(const std::string &name, const State &state)
        : name(name),
          state(state) {
    }
    bool operator<(const namedState& other) const {
        return std::tie(name, state) < std::tie(other.name, other.state);
    }

    friend bool operator==(const namedState &lhs, const namedState &rhs) {
        return lhs.name == rhs.name
               && lhs.state == rhs.state;
    }
};
struct Action {
    enum Type {SHIFT, REDUCE, ACCEPT, ERROR} type;
    int nexState;
    Production prod;

    Action() = default;
    Action(Type type, const Production &prod)
        : type(type),
          prod(prod), nexState(-1) {
    }

    Action(Type type, int nex_state)
        : type(type),
          nexState(nex_state), prod(Production()) {
    }

    Action(Type type)
        : type(type), nexState(0) {
    }
};

class CFG {
private:
    std::set<std::string> variables = {};
    std::set<std::string> terminals = {};
    std::string Start = "";
    std::set<Production> productions = {};
    std::set<std::string> nullableSymbols = {};
    std::vector<std::map<std::string, unsigned int>> GOTO;
    std::vector<std::map<std::string, Action>> ACTION;
    std::set<std::string> getLookahead(const std::vector<std::string>& lookaheadSymbol, const std::set<std::string>& oldLookahead);
    std::set<std::string> getNullable();
    void LookaheadHelper(const std::string& symbol, std::set<std::string>& newLookaheadTerminals,
        std::vector<std::string>& newLookaheadVariables, std::set<std::string>& nonWatchedVariables);
    void closure(State& state);
    bool sameKernel(const State& s1, const State& s2);
    void merge(State& s1, const State& s2);
    //void closure(const StateProduction& p, std::set<StateProduction>& productions);
    //std::set<std::string> getLookahead(const std::string& lookaheadNext, const std::set<std::string>& lookaheadPrevious);
    //std::set<std::string> FIRST(std::vector<std::string>& lookaheadNext);
public:
    [[nodiscard]] std::vector<std::map<std::string, unsigned int>> goto_() const {
        return GOTO;
    }

    [[nodiscard]] std::vector<std::map<std::string, Action>> action() const {
        return ACTION;
    }

    void saveTableToJSON(const std::string& filename);

    CFG(const std::string& filename);
    CFG(const std::set<std::string> &variables, const std::set<std::string> &terminals, const std::string &start,
        const std::set<Production> &productions)
        : variables(variables),
          terminals(terminals),
          Start(start),
          productions(productions) {
        nullableSymbols = getNullable();
    }
    void print() const;
    // construct the LR(1) items
    void toStates();
};


#endif //LALR_1__PARSER_CFG_H