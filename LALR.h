//
// Created by ruben on 2/12/2025.
//

#ifndef LALR_1__PARSER_CFG_H
#define LALR_1__PARSER_CFG_H
#include "common.h"


struct Production {
    string head;
    vector<string> body;
    Production() = default;
    Production(string h, vector<string> b)
            : head(move(h)), body(move(b)) {}
    bool operator<(const Production& other) const {
        if (head != other.head) return head < other.head;
        return body < other.body;
    }
    bool operator==(const Production& other) const {
        return head == other.head && body == other.body;
    }
};

struct StateProduction {
    string head;
    vector<string> body;
    unordered_set<string> lookahead; 

    StateProduction(string h, vector<string> b,
        unordered_set<string> la)
        : head(move(h)), body(move(b)), lookahead(move(la)) {}
    
    bool operator==(const StateProduction& other) const {
        return head == other.head && body == other.body;
    }
};

struct StateProductionHash {
    size_t operator()(const StateProduction& prod) const {
        size_t hash_val = hash<string>{}(prod.head);
        for (const auto& sym : prod.body) {
            hash_val ^= hash<string>{}(sym) + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
        }
        return hash_val;
    }
};

using State = unordered_set<StateProduction, StateProductionHash>;

struct StateHash {
    size_t operator()(const State& state) const {
        size_t seed = 0;
        StateProductionHash prod_hash;
        for (const auto& prod : state) {
            seed ^= prod_hash(prod) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }
};

struct namedState {
    string name;
    State state;
    namedState(const string &name, const State &state)
        : name(name),
          state(state) {
    }
};

struct Action {
    enum Type {SHIFT, REDUCE, ACCEPT, ERROR} type;
    int nexState;
    Production prod;

    Action() = default;
    Action(Type type, const Production &prod)
        : type(type), prod(prod), nexState(-1) {}

    Action(Type type, int nex_state)
        : type(type), nexState(nex_state), prod(Production()) {}

    Action(Type type)
        : type(type), nexState(0) {}
};

class CFG {
private:
    unordered_set<string> variables = {}; 
    unordered_set<string> terminals = {}; 
    string Start = "";
    vector<Production> productions = {}; 
    unordered_set<string> nullableSymbols = {}; 
    
    unordered_map<string, unordered_set<string>> firstSets; 

    vector<map<string, unsigned int>> GOTO;
    vector<map<string, Action>> ACTION;
    
    unordered_set<string> getNullable(); 
    unordered_map<string, unordered_set<string>> computeFirstSets();
    
    void closure(State& state);
    bool sameKernel(const State& s1, const State& s2);
    bool merge(State& s1, const State& s2);
    
public:
    [[nodiscard]] vector<map<string, unsigned int>> goto_() const { return GOTO; }
    [[nodiscard]] vector<map<string, Action>> action() const { return ACTION; }

    void saveTableToJSON(const string& filename);

    CFG(const string& filename);
    CFG(unordered_set<string> variables, unordered_set<string> terminals, string start,
        vector<Production> productions)
        : variables(move(variables)), terminals(move(terminals)), Start(move(start)),
          productions(move(productions)) 
    {
        nullableSymbols = getNullable();
        firstSets = computeFirstSets();
    }
    void print() const;
    void toStates();
};

#endif //LALR_1__PARSER_CFG_H