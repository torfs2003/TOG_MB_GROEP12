//
// Created by ruben on 2/12/2025.
//

#ifndef TOG_LALR_H
#define TOG_LALR_H
#include "common.h"


// Vertegenwoordigt een enkele grammaticaregel
struct Production {
    string head;          // Non-terminal
    vector<string> body;  // symbolen
    Production() = default;
    Production(string h, vector<string> b)
            : head(move(h)), body(move(b)) {}

    // Operator < is nodig om Producties als sleutel in een std::map of std::set te gebruiken
    // Zorgt voor een deterministische volgorde  
    bool operator<(const Production& other) const {
        if (head != other.head) return head < other.head;
        return body < other.body;
    }
    bool operator==(const Production& other) const {
        return head == other.head && body == other.body;
    }
};


// Vertegenwoordigt een LR(1)-item
// én een set van lookahead symbolen
struct StateProduction {
    string head;
    vector<string> body;
    unordered_set<string> lookahead; 

    StateProduction(string h, vector<string> b,
        unordered_set<string> la)
        : head(move(h)), body(move(b)), lookahead(move(la)) {}
    
    // Vergelijkt of twee items dezelfde kern hebben (head + body)
    bool operator==(const StateProduction& other) const {
        return head == other.head && body == other.body;
    }
};

    // Custom hash functie voor StateProduction
    // omdat C++ geen standaard hash heeft voor complexe structs
    // Combineert de hashes van de head en alle body-symbolen
    struct StateProductionHash {
    size_t operator()(const StateProduction& prod) const {
        size_t hash_val = hash<string>{}(prod.head);
        for (const auto& sym : prod.body) {
            // "Magic numbers" worden gebruikt om bits te mixen en botsingen te voorkomen (hash combine)
            hash_val ^= hash<string>{}(sym) + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
        }
        return hash_val;
    }
};

// Een State is een verzameling van unieke StateProductions (items)
using State = unordered_set<StateProduction, StateProductionHash>;

// Nodig om te checken of we een state al eerder zijn tegengekomen
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

// Hulpstructuur om een State een leesbare naam te geven
struct namedState {
    string name;
    State state;
    namedState(const string &name, const State &state)
        : name(name),
          state(state) {
    }
};

// Definieert een actie in de parsing tabel.
struct Action {
    enum Type {SHIFT, REDUCE, ACCEPT, ERROR} type;
    int nexState;
    Production prod;

    Action() = default;
    // REDUCE
    Action(Type type, const Production &prod)
        : type(type), prod(prod), nexState(-1) {}
    //SHIFT
    Action(Type type, int nex_state)
        : type(type), nexState(nex_state), prod(Production()) {}
    //ACCEPT/ERROR
    Action(Type type)
        : type(type), nexState(0) {}
};

// De klasse die de CFG inleest en de LALR(1) tabellen genereert.
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

#endif //TOG_LALR_H