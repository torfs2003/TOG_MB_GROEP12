#include "CFG.h"
#include "json.hpp"

using json = nlohmann::json;

CFG::CFG(const std::string &filename) {
    std::ifstream input(filename);
    json j;
    input >> j;
    for (const auto& variable : j["Variables"]) {
        variables.insert(variable);
    }
    for (const auto& Terminal : j["Terminals"]) {
        terminals.insert(Terminal);
    }
    Start = j["Start"];
    for (auto& production : j["Productions"]) {
        productions.emplace(production["head"], production["body"]);
    }
    nullableSymbols = getNullable();
}
void CFG::print() const {
    std::cout << "Variables: ";
    for (const auto& variable : variables) {
        std::cout << variable << ", ";
    }
    std::cout << std::endl << "Terminals: ";
    for (const auto& terminal : terminals) {
        std::cout << terminal << ", ";
    }
    std::cout << std::endl << "Start: " << Start;
    std::cout << std::endl << "Productions: " << std::endl;
    for (const auto& production : productions) {
        std::cout << "head: " << production.head << " " << "body: ";
        for (const auto& body : production.body) {
            std::cout << body << " ";
        }
        std::cout << std::endl;
    }
}

bool isTerminal(const std::string& x) {
    // terminals zijn vaak lowercase of symbolen
    // jij mag dit zelf bepalen:
    return !(x[0] >= 'A' && x[0] <= 'Z');
}

bool dotAtEnd(const std::string& body) {
    return !body.empty() && body.back() == '.';
}

std::string removeDot(const std::string& body) {
    std::string res = body;
    res.erase(std::remove(res.begin(), res.end(), '.'), res.end());
    return res;
}

void CFG::toStates() {
    std::string startHead = Start + "'";
    std::vector<std::string> startBody = {"." , Start};
    std::set<std::string> startLookahead = {"$"};
    std::vector<State> states = {{ StateProduction(startHead, startBody, startLookahead)}};
    std::vector<std::tuple<unsigned int, std::string, unsigned int>> transitions = {};
    for (int i = 0; i < states.size(); i++) {
        closure(states[i]);
        // 1. Zoek transitielabels
        std::set<std::string> transitionSymbols = {};
        for (const StateProduction& prod : states[i]) {
            const auto& b = prod.body;
            for (int p = 0; p < b.size() - 1; p++) {
                if (b[p] == ".") {
                    std::string sym = b[p+1];
                    if (sym != "ε")
                        transitionSymbols.insert(sym);
                    break;
                }
            }
        }

        // 2. Voor elk symbool -> nieuwe state berekenen
        for (const std::string& symbol : transitionSymbols) {
            State gotoState;
            // Dot verschuiven
            for (const StateProduction& prod : states[i]) {
                const auto& b = prod.body;
                for (int p = 0; p < b.size() - 1; p++) {
                    if (b[p] == "." && b[p+1] == symbol) {
                        std::vector<std::string> newBody = b;
                        std::swap(newBody[p], newBody[p+1]);
                        gotoState.insert(StateProduction(prod.head, newBody, prod.lookahead));
                        break;
                    }
                }
            }
            // 3. Closure op nieuwe state
            closure(gotoState);
            // 4. Bepalen of state nieuw is
            int index = -1;
            for (int s = 0; s < states.size(); s++) {
                if (states[s].size() == gotoState.size()) {
                    if (sameKernel(states[s], gotoState)) {
                        index = s;
                        merge(states[s], gotoState);
                        break;
                    }
                }
            }
            if (index == -1) {
                states.push_back(gotoState);
                index = states.size() - 1;
            }
            // 5. Transition opslaan
            transitions.emplace_back(i, symbol, index);
        }
    }
    // print de states en de transitions voor een test.
    std::cout << "De States: " << std::endl;
    for (int i=0; i<states.size(); i++) {
        std::cout << "I" << i << ":" << std::endl;
        for (const StateProduction& prod : states[i]) {
            std::cout << prod.head << "->";
            for (const std::string& s : prod.body) {
                std::cout << s << " ";
            }
            std::cout << ", ";
            for (const std::string& s : prod.lookahead) {
                std::cout << s << " ";
            }
            std::cout << std::endl;
        }
        std::cout << std::endl;
    }
    std::cout << "De Transitions: " << std::endl;
    for (int i=0; i<transitions.size(); i++) {
        std::cout << "go: " << std::get<0>(transitions[i]) << "\t with: " << std::get<1>(transitions[i]) <<
            "\n to: " << std::get<2>(transitions[i]) << std::endl;
    }

    // haal de overbodige states weg, en pas de transitie aan.
    std::vector<std::set<int>> LALR_States;
    for (int i = 0; i < states.size() - 1; i++) {
        for (int j = i + 1; j < states.size(); j++) {
            // Check of LR(0)-kern gelijk is
            if (!sameKernel(states[i], states[j]))
                continue;
            // Zoek of één van de sets i of j al bevat
            bool found = false;
            for (auto& group : LALR_States) {
                if (group.contains(i) || group.contains(j)) {
                    group.insert(i);
                    group.insert(j);
                    found = true;
                    break;
                }
            }
            // Nog geen groep gevonden → nieuwe groep maken
            if (!found) {
                LALR_States.push_back({i, j});
            }
        }
    }

    // laat de LALR states zien
    for (const std::set<int> s : LALR_States) {
        std::cout << "state: ";
        for (const int i : s) {
            std::cout << i << " ";
        }
        std::cout << std::endl;
    }
    // maak 1 grote vector van een pair met de samengevoegde state en de naam
    std::set<namedState> finalStatesSet = {};
    std::vector<int> indexen;
    indexen.reserve(states.size());
    for (int i = 1; i <= states.size(); ++i) {
        indexen.push_back(i);
    }
    for (std::set<int> s : LALR_States) {
        State newState;
        std::string name = "I";
        bool first = true;
        for (int i : s) {
            if (first) {
                newState = states[i];   // <-- kopie van eerste state
                first = false;
            } else {
                merge(newState, states[i]);  // <-- nu werkt merge() wél
            }
            indexen[i] = 0;
            name += std::to_string(i);
        }
        finalStatesSet.insert(namedState(name, newState));
    }
    for (int i : indexen) {
        if (i == 0) continue;
        else {
            finalStatesSet.insert(namedState("I"+std::to_string(i-1), states[i-1]));
        }
    }
    std::vector<namedState> FinalStates = {};
    for (const namedState& state : finalStatesSet) {
        FinalStates.push_back(state);
    }
    std::cout << "De FinalStates: " << std::endl;
    int blablabla=0;
    for (const namedState& s : FinalStates) {
        std::cout << "index: " << blablabla << " | name: " << s.name << ":" << std::endl;
        for (const StateProduction& production : s.state) {
            std::cout << production.head << "->";
            for (const std::string& s : production.body) {
                std::cout << s << " ";
            }
            std::cout << ", ";
            for (const std::string& s1 : production.lookahead) {
                std::cout << s1 << " ";
            }
            std::cout << std::endl;
        }
        blablabla++;
    }
    // maak de table
    std::set<std::tuple<std::string, std::string, std::string>> newTransitions = {};
    for (const auto& transition : transitions) {
        unsigned int from = std::get<0>(transition);
        unsigned int to   = std::get<2>(transition);
        std::string symbol = std::get<1>(transition);
        std::string newFrom = "I";
        std::string newTo = "I";
        for (const std::set<int>& indexes : LALR_States) {
            if (indexes.contains(from)) {
                for (int i : indexes) {
                    newFrom += std::to_string(i);
                }
            }
            if (indexes.contains(to)) {
                for (int i : indexes) {
                    newTo += std::to_string(i);
                }
            }
        }
        if (newFrom.size() == 1) {newFrom += std::to_string(from);}
        if (newTo.size() == 1) {newTo += std::to_string(to);}
        newTransitions.insert(std::make_tuple(newFrom, symbol, newTo));
    }
    std::cout << "De NewTransitions: " << std::endl;
    for (const std::tuple<std::string, std::string, std::string>& transition : newTransitions) {
        std::cout << "from: " << std::get<0>(transition) << "\t to: " << std::get<2>(transition) << "\t with: " << std::get<1>(transition) << std::endl;
    }
    GOTO.resize(FinalStates.size());
    // Maak mapping naam → index
    std::unordered_map<std::string, unsigned int> nameToIndex;
    for (unsigned int i = 0; i < FinalStates.size(); i++) {
        nameToIndex[FinalStates[i].name] = i;
    }
    // de GOTO-tabel
    for (const auto& action : newTransitions) {
        std::string fromName = std::get<0>(action);
        std::string symbol   = std::get<1>(action);
        std::string toName   = std::get<2>(action);
        // GOTO alleen voor niet-terminals!
        if (terminals.contains(symbol)) continue;
        unsigned int fromIndex = nameToIndex[fromName];
        unsigned int toIndex   = nameToIndex[toName];
        GOTO[fromIndex][symbol] = toIndex;
    }
    for (unsigned int k = 0; k < GOTO.size(); k++) {
        std::cout << "State " << k << ":\n";

        for (const auto& entry : GOTO[k]) {
            const std::string& nonterminal = entry.first;
            unsigned int nextState = entry.second;

            std::cout << "  GOTO[" << k << "][" << nonterminal
                      << "] = " << nextState << "\n";
        }
    }
    ACTION.resize(FinalStates.size());
    // alle reduces toevoegen en accept
    for (const namedState& state : FinalStates) {
        for (const StateProduction& production : state.state) {
            if (production.body[production.body.size()-1] == ".") {
                int index = nameToIndex[state.name];
                if (production.body[production.body.size()-2] == Start) {
                    for (const std::string& s : production.lookahead) {
                        ACTION[index][s] = Action{Action::ACCEPT};
                    }
                } else {
                    Production prod;
                    std::vector<std::string> bodyNoDot(production.body.begin(), production.body.end()-1);
                    for (const Production& p : productions) {
                        if (p.head == production.head && p.body == bodyNoDot) {
                            prod = p;
                            break;
                        }
                    }
                    for (const std::string& s : production.lookahead) {
                        ACTION[index][s] = Action{Action::REDUCE, prod};
                    }
                }
            }
        }
    }
    // alle shifts toevoegen
    for (const auto& action : newTransitions) {
        std::string fromName = std::get<0>(action);
        std::string symbol   = std::get<1>(action);
        std::string toName   = std::get<2>(action);
        // ACTION alleen voor terminals!
        if (!terminals.contains(symbol)) continue;
        unsigned int fromIndex = nameToIndex[fromName];
        int toIndex   = nameToIndex[toName];
        ACTION[fromIndex][symbol] = Action{Action::SHIFT, toIndex};
    }
    // print de table
    std::cout << "===== ACTION TABLE =====\n\n";
    for (int state = 0; state < ACTION.size(); state++) {

        std::cout << "State " << state << ":\n";

        if (ACTION[state].empty()) {
            std::cout << "   (no actions)\n\n";
            continue;
        }

        for (const auto& [symbol, act] : ACTION[state]) {

            std::cout << "   ACTION[" << state << "][" << symbol << "] = ";

            switch (act.type) {

                case Action::SHIFT:
                    std::cout << "shift " << act.nexState;
                    break;

                case Action::REDUCE:
                    std::cout << "reduce "
                              << act.prod.head << " -> ";
                    for (const std::string& s : act.prod.body) {
                        std::cout << s << " ";
                    }
                    std::cout << "\n";
                    break;

                case Action::ACCEPT:
                    std::cout << "accept";
                    break;

                case Action::ERROR:
                default:
                    std::cout << "error";
                    break;
            }

            std::cout << "\n";
        }

        std::cout << "\n";
    }
}

bool CFG::sameKernel(const State& s1, const State& s2) {
    if (s1.size() != s2.size()) return false;
    auto it1 = s1.begin();
    auto it2 = s2.begin();
    while (it1 != s1.end()) {
        // head en body moeten identiek zijn
        if (it1->head != it2->head || it1->body != it2->body) {
            return false;
        }
        ++it1; ++it2;
    }
    return true;
}
void CFG::merge(State &s1, const State &s2) {
    if (s1.size() != s2.size()) return;
    auto it1 = s1.begin();
    auto it2 = s2.begin();
    while (it1 != s1.end()) {
        if (it1->head == it2->head && it1->body == it2->body) {
            const_cast<std::set<std::string>&>(it1->lookahead).insert(it2->lookahead.begin(), it2->lookahead.end());
            /*if (it1->lookahead.size()>1) {
                const_cast<std::set<std::string>&>(it1->lookahead).erase("$");
            }*/
        }
        it1++; it2++;
    }
}
void CFG::closure(State &state) {
    bool changed = true;
    while (changed) {
        changed = false;
        // Gebruik een tijdelijke lijst van items om toe te voegen, in plaats van een volledige State (set).
        // Dit is iets minder kritisch dan de Lookahead-logica, maar kan helpen.
        std::vector<StateProduction> itemsToAdd; 
        
        for (const StateProduction &prod : state) {
            // Zoek het punt (logica is correct)
            for (int i = 0; i < prod.body.size() - 1; i++) {
                if (prod.body[i] == ".") {
                    const std::string &nextSymbol = prod.body[i + 1];
                    
                    if (!variables.contains(nextSymbol))
                        break;
                        
                    // β = rest na het symbool
                    std::vector<std::string> beta;
                    if (i + 2 <= prod.body.size())
                        beta = { prod.body.begin() + i + 2, prod.body.end() };
                        
                    // lookahead voor de nieuwe items
                    // OPMERKING: getLookahead maakt al een kopie van LA.
                    std::set<std::string> LA = getLookahead(beta, prod.lookahead); 
                    
                    for (const Production &p : productions) {
                        if (p.head == nextSymbol) {
                            std::vector<std::string> newBody = {"."};
                            newBody.insert(newBody.end(), p.body.begin(), p.body.end());
                            StateProduction newProd(nextSymbol, newBody, LA);
                            
             
                            auto it = state.find(newProd); // Zoek de kern (head/body)
                            if (it == state.end()) {
                                itemsToAdd.push_back(newProd); // Voeg toe aan de batch
                            }
                            else {
                                std::set<std::string> mergedLA = it->lookahead;
                                size_t oldSize = mergedLA.size();
                                mergedLA.insert(LA.begin(), LA.end());
                                
                                if (mergedLA.size() > oldSize) {
                                    StateProduction updated = *it;
                                    state.erase(it);
                                    updated.lookahead = mergedLA;
                                    state.insert(updated);
                                    changed = true; // Loop moet verder gaan
                                }
                            }
                        }
                    }
                    break;
                }
            }
        }
        
        for (const StateProduction &item : itemsToAdd) {
            if (state.find(item) == state.end()) {
                state.insert(item);
                changed = true;
            } 

        }
    }
}
std::set<std::string> CFG::getLookahead(const std::vector<std::string>& beta, const std::set<std::string> &oldLookahead) {
    std::set<std::string> newLookaheadTerminals = {};
    std::vector<std::string> newLookaheadVariables = {};
    std::set<std::string> nonWatchedVariables = variables;
    for (const std::string& s : beta) {
        if (s == "ε") {
            continue;
        }
        // als s een terminal is, dan mogen we stoppen en returnen we alles wat we hebben gegenereerd.
        if (terminals.contains(s)) {
            newLookaheadTerminals.insert(s);
            return newLookaheadTerminals;
        }
        if (variables.contains(s)) {
            LookaheadHelper(s, newLookaheadTerminals,newLookaheadVariables, nonWatchedVariables);
        }
        if (!nullableSymbols.contains(s)) {
            return newLookaheadTerminals;
        }
    }
    // return de unie van newLookaheadTerminals en oldLookahead:
    newLookaheadTerminals.insert(oldLookahead.begin(), oldLookahead.end());
    newLookaheadTerminals.erase("ε");
    if (newLookaheadTerminals.size() > 1) {
        newLookaheadTerminals.erase("$");
    }
    return newLookaheadTerminals;
}
std::set<std::string> CFG::getNullable() {
    std::set<std::string> nullable = {};
    bool done = false;
    while (!done) {
        done = true;
        for (const Production& production : productions) {
            if (production.body.size() == 1 && production.body[0] == "ε") {
                nullable.insert(production.head);
                done = false;
            } else {
                bool nul = true;
                for (const std::string& s : production.body) {
                    if (terminals.contains(s)) {
                        nul = false;
                        break;
                    }
                    if (!nullable.contains(s)) {
                        nul = false;
                        break;
                    }
                }
                if (nul) {
                    nullable.insert(production.head);
                    done = false;
                }
            }
        }
    }
    return nullable;
}
void CFG::LookaheadHelper(const std::string &symbol, std::set<std::string> &newLookaheadTerminals,
    std::vector<std::string> &newLookaheadVariables, std::set<std::string> &nonWatchedVariables) {
    for (const Production& production : productions) {
        if (production.head == symbol) {
            for (const std::string& s : production.body) {
                if (terminals.contains(s)) {
                    newLookaheadTerminals.insert(s);
                    break;
                }
                if (variables.contains(s) && nonWatchedVariables.contains(s)) {
                    newLookaheadVariables.push_back(s);
                    nonWatchedVariables.erase(s);
                    LookaheadHelper(s, newLookaheadTerminals, newLookaheadVariables, nonWatchedVariables);
                }
                if (!nullableSymbols.contains(s)) {
                    break;
                }
            }
        }
    }
}

void CFG::saveTableToJSON(const std::string& filename) {
    json root;
    
    // 1. Serialize ACTION Table
    // ACTION is a vector<map<string, Action>>
    for (int i = 0; i < ACTION.size(); i++) {
        for (auto const& [symbol, action] : ACTION[i]) {
            std::string stateStr = std::to_string(i);
            
            // We create a JSON object for this specific action
            json actionObj;
            
            if (action.type == Action::SHIFT) {
                actionObj["type"] = "SHIFT";
                actionObj["state"] = action.nexState;
            } 
            else if (action.type == Action::REDUCE) {
                actionObj["type"] = "REDUCE";
                actionObj["lhs"] = action.prod.head; // Head of production
                actionObj["rhs"] = action.prod.body; // Body (vector of strings)
            } 
            else if (action.type == Action::ACCEPT) {
                actionObj["type"] = "ACCEPT";
            }
            
            // Store it: root["action"][state_index][symbol] = { ... }
            root["action_table"][stateStr][symbol] = actionObj;
        }
    }

    for (int i = 0; i < GOTO.size(); i++) {
        for (auto const& [nonTerminal, nextState] : GOTO[i]) {
            std::string stateStr = std::to_string(i);
            root["goto_table"][stateStr][nonTerminal] = nextState;
        }
    }

    std::ofstream file(filename);
    file << root.dump(4); // dump(4) adds pretty indentation
    std::cout << "Parse table saved to " << filename << std::endl;
}