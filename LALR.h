//
// Created by ruben on 2/12/2025.
//

#ifndef LALR_1__PARSER_CFG_H
#define LALR_1__PARSER_CFG_H

#include <iostream>
#include <vector>
#include <fstream>
#include <map>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <tuple>
#include <utility>
#include <filesystem>

struct Production {
    std::string head;
    std::vector<std::string> body;
    Production() = default;
    Production(std::string h, std::vector<std::string> b)
            : head(std::move(h)), body(std::move(b)) {}
    bool operator<(const Production& other) const {
        if (head != other.head) return head < other.head;
        return body < other.body;
    }
    bool operator==(const Production& other) const {
        return head == other.head && body == other.body;
    }
};

struct StateProduction {
    std::string head;
    std::vector<std::string> body;
    // For performance: use unordered_set for lookahead
    std::unordered_set<std::string> lookahead; 

    // Constructor simplified (assumes lookahead is passed as unordered_set)
    StateProduction(std::string h, std::vector<std::string> b,
        std::unordered_set<std::string> la)
        : head(std::move(h)), body(std::move(b)), lookahead(std::move(la)) {}
    
    // For kernel comparison (used in the unordered_set find)
    bool operator==(const StateProduction& other) const {
        return head == other.head && body == other.body;
    }
};

// Custom Hash for StateProduction (only based on the LR(0) kernel)
struct StateProductionHash {
    size_t operator()(const StateProduction& prod) const {
        size_t hash_val = std::hash<std::string>{}(prod.head);
        for (const auto& sym : prod.body) {
            hash_val ^= std::hash<std::string>{}(sym) + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
        }
        return hash_val;
    }
};

// Use unordered_set for states for O(1) average lookup/insertion (Performance critical)
using State = std::unordered_set<StateProduction, StateProductionHash>;

// Custom Hash for State (needed for the kernelIndexMap)
struct StateHash {
    size_t operator()(const State& state) const {
        size_t seed = 0;
        StateProductionHash prod_hash;
        for (const auto& prod : state) {
            // Combine hash of each item's kernel
            seed ^= prod_hash(prod) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
        return seed;
    }
};

struct namedState {
    std::string name;
    State state;
    // ... (rest of namedState remains as it was)
    namedState(const std::string &name, const State &state)
        : name(name),
          state(state) {
    }
    // Note: comparison for namedState should be avoided on 'state' if State is unordered_set, 
    // unless you want to iterate/compare contents (which is slow).
    // I removed the operator< and == overloads as they contradict the unordered_set type.
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
    std::unordered_set<std::string> variables = {}; // Use unordered_set
    std::unordered_set<std::string> terminals = {}; // Use unordered_set
    std::string Start = "";
    std::vector<Production> productions = {}; // Change to vector for fast iteration and indexing
    std::unordered_set<std::string> nullableSymbols = {}; // Use unordered_set
    
    // Pre-calculated sets for O(1) closure lookups
    std::unordered_map<std::string, std::unordered_set<std::string>> firstSets; 

    std::vector<std::map<std::string, unsigned int>> GOTO;
    std::vector<std::map<std::string, Action>> ACTION;
    
    // Removed old, inefficient lookahead helpers
    
    std::unordered_set<std::string> getNullable(); // Returns unordered_set
    std::unordered_map<std::string, std::unordered_set<std::string>> computeFirstSets();
    
    void closure(State& state);
    bool sameKernel(const State& s1, const State& s2);
    bool merge(State& s1, const State& s2);
    
public:
    [[nodiscard]] std::vector<std::map<std::string, unsigned int>> goto_() const { return GOTO; }
    [[nodiscard]] std::vector<std::map<std::string, Action>> action() const { return ACTION; }

    void saveTableToJSON(const std::string& filename);

    CFG(const std::string& filename);
    // Simplified constructor to match new private types
    CFG(std::unordered_set<std::string> variables, std::unordered_set<std::string> terminals, std::string start,
        std::vector<Production> productions)
        : variables(std::move(variables)), terminals(std::move(terminals)), Start(std::move(start)),
          productions(std::move(productions)) 
    {
        nullableSymbols = getNullable();
        firstSets = computeFirstSets();
    }
    void print() const;
    void toStates();
};

#endif //LALR_1__PARSER_CFG_H