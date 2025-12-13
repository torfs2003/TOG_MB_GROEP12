#include "LALR.h"
#include "json.hpp"


using json = nlohmann::json;


CFG::CFG(const std::string &filename) {
    std::ifstream input(filename);
    json j;
    input >> j;
    
    for (const auto& variable : j["Variables"]) {
        variables.insert(variable.get<std::string>());
    }
    for (const auto& terminal : j["Terminals"]) {
        terminals.insert(terminal.get<std::string>());
    }
    Start = j["Start"];
    // Using a vector of Productions here for easier indexing/iteration
    for (const auto& production : j["Productions"]) {
        productions.push_back({production["head"], production["body"].get<std::vector<std::string>>()});
    }
    
    nullableSymbols = getNullable();
    firstSets = computeFirstSets();
}


std::unordered_map<std::string, std::unordered_set<std::string>> CFG::computeFirstSets() {
    std::unordered_map<std::string, std::unordered_set<std::string>> first;
    bool changed = true;

    for (const auto& t : terminals) first[t].insert(t);
    for (const auto& v : variables) first[v] = {};

    while (changed) {
        changed = false;
        for (const Production& p : productions) {
            const std::string& head = p.head;
            size_t old_size = first[head].size();
            
            for (const std::string& sym : p.body) {
                if (terminals.count(sym)) {
                    first[head].insert(sym);
                    break;
                }
                if (variables.count(sym)) {
                    for (const auto& term : first[sym]) {
                        if (term != "ε") first[head].insert(term);
                    }
                    if (!nullableSymbols.count(sym)) break;
                }
            }
            if (first[head].size() > old_size) changed = true;
        }
    }
    return first;
}

std::unordered_set<std::string> CFG::getNullable() {
    std::unordered_set<std::string> nullable = {};
    bool changed = true;
    while (changed) {
        changed = false;
        for (const Production& production : productions) {
            bool is_nullable = true;
            for (const std::string& s : production.body) {
                if (terminals.count(s) || (variables.count(s) && !nullable.count(s))) {
                    is_nullable = false;
                    break;
                }
            }
            if (is_nullable && !nullable.count(production.head)) {
                nullable.insert(production.head);
                changed = true;
            }
        }
    }
    return nullable;
}

void CFG::closure(State &state) {
    bool changed = true;
    while (changed) {
        changed = false;
        

        std::vector<StateProduction> current_items(state.begin(), state.end());
        
        for (const StateProduction &prod : current_items) {
            
            int dot_pos = -1;
            for (size_t i = 0; i < prod.body.size(); i++) {
                if (prod.body[i] == ".") {
                    dot_pos = i;
                    break;
                }
            }

            if (dot_pos != -1 && dot_pos + 1 < prod.body.size()) {
                const std::string &nextSymbol = prod.body[dot_pos + 1];
                
                if (variables.count(nextSymbol)) {
                    
                    std::vector<std::string> beta_vector;
                    if (dot_pos + 2 < prod.body.size()) {
                        beta_vector.assign(prod.body.begin() + dot_pos + 2, prod.body.end());
                    }
                    
                    std::unordered_set<std::string> LA;
                    bool beta_is_nullable = true;

                    for (const std::string& sym : beta_vector) {
                        if (terminals.count(sym)) {
                            LA.insert(sym);
                            beta_is_nullable = false;
                            break;
                        } else if (variables.count(sym)) {
                            for (const std::string& term : firstSets[sym]) {
                                if (term != "ε") LA.insert(term);
                            }
                            if (!nullableSymbols.count(sym)) {
                                beta_is_nullable = false;
                                break;
                            }
                        }
                    }
                    if (beta_is_nullable) {
                        LA.insert(prod.lookahead.begin(), prod.lookahead.end());
                    }

                    for (const Production &p : productions) {
                        if (p.head == nextSymbol) {
                            std::vector<std::string> newBody = {"."};
                            newBody.insert(newBody.end(), p.body.begin(), p.body.end());
                            StateProduction newProd{p.head, newBody, LA};
                            
                            auto it = state.find(newProd); // O(1) average lookup
                            if (it == state.end()) {
                                state.insert(std::move(newProd));
                                changed = true;
                            } else {
                                // Item exists (same kernel) -> Merge lookahead
                                StateProduction existingProd = *it;
                                size_t oldSize = existingProd.lookahead.size();
                                existingProd.lookahead.insert(LA.begin(), LA.end());
                                
                                if (existingProd.lookahead.size() > oldSize) {
                                    // Lookahead changed -> remove old, insert new
                                    state.erase(it);
                                    state.insert(std::move(existingProd));
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}



// sameKernel: Faster comparison using the StateProduction's operator==
bool CFG::sameKernel(const State& s1, const State& s2) {
    if (s1.size() != s2.size()) return false;
    for (const auto& prod1 : s1) {
        if (s2.find(prod1) == s2.end()) {
            return false;
        }
    }
    return true;
}

// Change return type from void to bool
bool CFG::merge(State &s1, const State &s2) {
    bool changed = false;
    State merged_s1 = s1;
    s1.clear();

    for (const auto& prod1 : merged_s1) {
        auto it2 = s2.find(prod1);
        if (it2 != s2.end()) {
            // Kernel matches, merge lookaheads
            StateProduction merged_prod = prod1;
            size_t oldSize = merged_prod.lookahead.size();
            
            // Insert lookaheads from s2 into the merged product
            merged_prod.lookahead.insert(it2->lookahead.begin(), it2->lookahead.end());
            
            // Check if size increased (meaning we found new lookaheads)
            if (merged_prod.lookahead.size() > oldSize) {
                changed = true;
            }
            s1.insert(merged_prod);
        } else {
            s1.insert(prod1);
        }
    }
    return changed;
}

void CFG::toStates() {
    // 1. Initialization
    std::unordered_map<State, unsigned int, StateHash> kernelIndexMap;

    // Define the Augmented Start Symbol S'
    std::string startHead = Start + "'";
    std::vector<std::string> startBody = {"." , Start};
    std::unordered_set<std::string> startLookahead = {"$"};
    
    std::vector<State> states;
    std::vector<std::tuple<unsigned int, std::string, unsigned int>> transitions = {};

    State initialState = {{ StateProduction{startHead, startBody, startLookahead}}};
    closure(initialState);
    states.push_back(initialState);
    kernelIndexMap.emplace(initialState, 0);

    // 2. Generate LR(0) State Structure
    for (unsigned int i = 0; i < states.size(); i++) {
        std::unordered_set<std::string> transitionSymbols = {}; 
        
        for (const StateProduction& prod : states[i]) {
            const auto& b = prod.body;
            for (size_t p = 0; p < b.size() - 1; p++) {
                if (b[p] == ".") {
                    std::string sym = b[p+1];
                    if (sym != "ε") transitionSymbols.insert(sym);
                    break;
                }
            }
        }

        for (const std::string& symbol : transitionSymbols) {
            State gotoState;
            for (const StateProduction& prod : states[i]) {
                const auto& b = prod.body;
                for (size_t p = 0; p < b.size() - 1; p++) {
                    if (b[p] == "." && b[p+1] == symbol) {
                        std::vector<std::string> newBody = b;
                        std::swap(newBody[p], newBody[p+1]);
                        gotoState.insert(StateProduction(prod.head, newBody, prod.lookahead));
                        break;
                    }
                }
            }
            
            closure(gotoState);
            
            unsigned int index = -1;
            auto it = kernelIndexMap.find(gotoState);
            
            if (it != kernelIndexMap.end()) {
                index = it->second;
                merge(states[index], gotoState); 
            } else {
                states.push_back(gotoState);
                index = states.size() - 1;
                kernelIndexMap.emplace(gotoState, index); 
            }
            transitions.emplace_back(i, symbol, index);
        }
    }

    // 2.5 Propagate Lookaheads
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& trans : transitions) {
            unsigned int fromIdx = std::get<0>(trans);
            std::string symbol   = std::get<1>(trans);
            unsigned int toIdx   = std::get<2>(trans);

            State tempGoto;
            for (const StateProduction& prod : states[fromIdx]) {
                const auto& b = prod.body;
                for (size_t p = 0; p < b.size() - 1; p++) {
                    if (b[p] == "." && b[p+1] == symbol) {
                        std::vector<std::string> newBody = b;
                        std::swap(newBody[p], newBody[p+1]);
                        tempGoto.insert(StateProduction(prod.head, newBody, prod.lookahead));
                        break;
                    }
                }
            }
            closure(tempGoto);
            if (merge(states[toIdx], tempGoto)) {
                changed = true;
            }
        }
    }

    // 3. Calculate LALR States (Merging Kernels)
    std::vector<std::set<int>> LALR_States;
    std::vector<bool> stateHandled(states.size(), false);

    for (int i = 0; i < states.size(); i++) {
        if (stateHandled[i]) continue;
        
        std::set<int> currentGroup;
        currentGroup.insert(i);
        stateHandled[i] = true;

        for (int j = i + 1; j < states.size(); j++) {
            if (!stateHandled[j] && sameKernel(states[i], states[j])) {
                currentGroup.insert(j);
                stateHandled[j] = true;
            }
        }
        LALR_States.push_back(currentGroup);
    }

    // 4. Create Final Named States
    std::vector<namedState> FinalStates = {};
    for (const std::set<int>& s : LALR_States) {
        State newState;
        std::string name = "I";
        bool first = true;
        
        for (int i : s) {
            if (first) {
                newState = states[i];
                first = false;
            } else {
                merge(newState, states[i]);
            }
            name += std::to_string(i);
        }
        FinalStates.push_back(namedState(name, newState));
    }

    // 5. Build Action/Goto Tables
    std::unordered_map<std::string, unsigned int> nameToIndex;
    for (unsigned int i = 0; i < FinalStates.size(); i++) {
        nameToIndex[FinalStates[i].name] = i;
    }

    // Map old state indices to new LALR state indices
    std::vector<int> oldToNewIndex(states.size());
    for(int i=0; i<states.size(); ++i) {
        for(int grpIdx = 0; grpIdx < LALR_States.size(); ++grpIdx) {
            if(LALR_States[grpIdx].count(i)) {
                oldToNewIndex[i] = grpIdx;
                break;
            }
        }
    }

    GOTO.assign(FinalStates.size(), {});
    ACTION.assign(FinalStates.size(), {});

    // Fill GOTO and ACTION (Shift)
    for (const auto& transition : transitions) {
        unsigned int fromOld = std::get<0>(transition);
        std::string symbol   = std::get<1>(transition);
        unsigned int toOld   = std::get<2>(transition);

        unsigned int fromNew = oldToNewIndex[fromOld];
        unsigned int toNew   = oldToNewIndex[toOld];

        if (terminals.count(symbol)) {
            ACTION[fromNew][symbol] = Action{Action::SHIFT, (int)toNew};
        } else {
            GOTO[fromNew][symbol] = toNew;
        }
    }

    // Fill ACTION (Reduce/Accept)
    for (unsigned int i = 0; i < FinalStates.size(); i++) {
        const namedState& state = FinalStates[i];
        
        for (const StateProduction& production : state.state) {
            // Check if dot is at the end
            if (!production.body.empty() && production.body.back() == ".") {
                
                // Case 1: ACCEPT
                // We check if the HEAD is the augmented start symbol (Start + "'")
                if (production.head == startHead) {
                    for (const std::string& s : production.lookahead) {
                        if (s == "$") {
                            ACTION[i][s] = Action{Action::ACCEPT};
                        }
                    }
                    continue; // Done with this item
                }

                // Case 2: REDUCE
                // Find original production to store in the action
                std::vector<std::string> bodyNoDot(production.body.begin(), production.body.end()-1);
                Production originalProd;
                bool found = false;
                
                for (const Production& p : productions) {
                    if (p.head == production.head && p.body == bodyNoDot) {
                        originalProd = p;
                        found = true;
                        break;
                    }
                }
                
                if (found) {
                    for (const std::string& s : production.lookahead) {
                        bool skip = false;

                        if (ACTION[i].count(s)) {
                            const Action& existing = ACTION[i][s];
                            
                            // SHIFT priority: If we can shift, do NOT overwrite with reduce.
                            if (existing.type == Action::SHIFT) {
                                skip = true; 
                            } 
                            // Reduce/Reduce Conflict detection
                            else if (existing.type == Action::REDUCE) {
                                if (existing.prod.head != originalProd.head || existing.prod.body != originalProd.body) {
                                    std::cerr << "CRITICAL WARNING: Reduce/Reduce conflict in State " << i 
                                              << " on symbol '" << s << "'.\n"
                                              << "  Existing: " << existing.prod.head << " -> ...\n"
                                              << "  New:      " << originalProd.head << " -> ...\n";
                                    skip = true; // Keep existing
                                }
                            }
                            else if (existing.type == Action::ACCEPT) {
                                skip = true;
                            }
                        }

                        if (!skip) {
                            ACTION[i][s] = Action{Action::REDUCE, originalProd};
                        }
                    }
                }
            }
        }
    }

    // Debug Print (Optional)
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
                case Action::SHIFT:  std::cout << "shift " << act.nexState; break;
                case Action::REDUCE: std::cout << "reduce " << act.prod.head << " -> ..."; break;
                case Action::ACCEPT: std::cout << "accept"; break;
                default: std::cout << "error"; break;
            }
            std::cout << "\n";
        }
        std::cout << "\n";
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