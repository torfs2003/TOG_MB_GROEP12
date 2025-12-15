#include "LALR.h"
#include "json.hpp"



CFG::CFG(const string &filename) {
    ifstream input(filename);
    json j;
    input >> j;
    
    for (const auto& variable : j["Variables"]) {
        variables.insert(variable.get<string>());
    }
    for (const auto& terminal : j["Terminals"]) {
        terminals.insert(terminal.get<string>());
    }
    Start = j["Start"];
    for (const auto& production : j["Productions"]) {
        productions.push_back({production["head"], production["body"].get<vector<string>>()});
    }
    
    nullableSymbols = getNullable();
    firstSets = computeFirstSets();
}


unordered_map<string, unordered_set<string>> CFG::computeFirstSets() {
    unordered_map<string, unordered_set<string>> first;
    bool changed = true;

    for (const auto& t : terminals) first[t].insert(t);
    for (const auto& v : variables) first[v] = {};

    while (changed) {
        changed = false;
        for (const Production& p : productions) {
            const string& head = p.head;
            size_t old_size = first[head].size();
            
            for (const string& sym : p.body) {
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

unordered_set<string> CFG::getNullable() {
    unordered_set<string> nullable = {};
    bool changed = true;
    while (changed) {
        changed = false;
        for (const Production& production : productions) {
            bool is_nullable = true;
            for (const string& s : production.body) {
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
        

        vector<StateProduction> current_items(state.begin(), state.end());
        
        for (const StateProduction &prod : current_items) {
            
            int dot_pos = -1;
            for (size_t i = 0; i < prod.body.size(); i++) {
                if (prod.body[i] == ".") {
                    dot_pos = i;
                    break;
                }
            }

            if (dot_pos != -1 && dot_pos + 1 < prod.body.size()) {
                const string &nextSymbol = prod.body[dot_pos + 1];
                
                if (variables.count(nextSymbol)) {
                    
                    vector<string> beta_vector;
                    if (dot_pos + 2 < prod.body.size()) {
                        beta_vector.assign(prod.body.begin() + dot_pos + 2, prod.body.end());
                    }
                    
                    unordered_set<string> LA;
                    bool beta_is_nullable = true;

                    for (const string& sym : beta_vector) {
                        if (terminals.count(sym)) {
                            LA.insert(sym);
                            beta_is_nullable = false;
                            break;
                        } else if (variables.count(sym)) {
                            for (const string& term : firstSets[sym]) {
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
                            vector<string> newBody = {"."};
                            newBody.insert(newBody.end(), p.body.begin(), p.body.end());
                            StateProduction newProd{p.head, newBody, LA};
                            
                            auto it = state.find(newProd); 
                            if (it == state.end()) {
                                state.insert(move(newProd));
                                changed = true;
                            } else {
                                StateProduction existingProd = *it;
                                size_t oldSize = existingProd.lookahead.size();
                                existingProd.lookahead.insert(LA.begin(), LA.end());
                                
                                if (existingProd.lookahead.size() > oldSize) {
                                    state.erase(it);
                                    state.insert(move(existingProd));
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



bool CFG::sameKernel(const State& s1, const State& s2) {
    if (s1.size() != s2.size()) return false;
    for (const auto& prod1 : s1) {
        if (s2.find(prod1) == s2.end()) {
            return false;
        }
    }
    return true;
}

bool CFG::merge(State &s1, const State &s2) {
    bool changed = false;
    State merged_s1 = s1;
    s1.clear();

    for (const auto& prod1 : merged_s1) {
        auto it2 = s2.find(prod1);
        if (it2 != s2.end()) {
            StateProduction merged_prod = prod1;
            size_t oldSize = merged_prod.lookahead.size();
            
            merged_prod.lookahead.insert(it2->lookahead.begin(), it2->lookahead.end());
            
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
    unordered_map<State, unsigned int, StateHash> kernelIndexMap;

    string startHead = Start + "'";
    vector<string> startBody = {"." , Start};
    unordered_set<string> startLookahead = {"$"};
    
    vector<State> states;
    vector<tuple<unsigned int, string, unsigned int>> transitions = {};

    State initialState = {{ StateProduction{startHead, startBody, startLookahead}}};
    closure(initialState);
    states.push_back(initialState);
    kernelIndexMap.emplace(initialState, 0);

    for (unsigned int i = 0; i < states.size(); i++) {
        unordered_set<string> transitionSymbols = {}; 
        
        for (const StateProduction& prod : states[i]) {
            const auto& b = prod.body;
            for (size_t p = 0; p < b.size() - 1; p++) {
                if (b[p] == ".") {
                    string sym = b[p+1];
                    if (sym != "ε") transitionSymbols.insert(sym);
                    break;
                }
            }
        }

        for (const string& symbol : transitionSymbols) {
            State gotoState;
            for (const StateProduction& prod : states[i]) {
                const auto& b = prod.body;
                for (size_t p = 0; p < b.size() - 1; p++) {
                    if (b[p] == "." && b[p+1] == symbol) {
                        vector<string> newBody = b;
                        swap(newBody[p], newBody[p+1]);
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

    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& trans : transitions) {
            unsigned int fromIdx = get<0>(trans);
            string symbol   = get<1>(trans);
            unsigned int toIdx   = get<2>(trans);

            State tempGoto;
            for (const StateProduction& prod : states[fromIdx]) {
                const auto& b = prod.body;
                for (size_t p = 0; p < b.size() - 1; p++) {
                    if (b[p] == "." && b[p+1] == symbol) {
                        vector<string> newBody = b;
                        swap(newBody[p], newBody[p+1]);
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

    vector<set<int>> LALR_States;
    vector<bool> stateHandled(states.size(), false);

    for (int i = 0; i < states.size(); i++) {
        if (stateHandled[i]) continue;
        
        set<int> currentGroup;
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

    vector<namedState> FinalStates = {};
    for (const set<int>& s : LALR_States) {
        State newState;
        string name = "I";
        bool first = true;
        
        for (int i : s) {
            if (first) {
                newState = states[i];
                first = false;
            } else {
                merge(newState, states[i]);
            }
            name += to_string(i);
        }
        FinalStates.push_back(namedState(name, newState));
    }

    unordered_map<string, unsigned int> nameToIndex;
    for (unsigned int i = 0; i < FinalStates.size(); i++) {
        nameToIndex[FinalStates[i].name] = i;
    }

    vector<int> oldToNewIndex(states.size());
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

    for (const auto& transition : transitions) {
        unsigned int fromOld = get<0>(transition);
        string symbol   = get<1>(transition);
        unsigned int toOld   = get<2>(transition);

        unsigned int fromNew = oldToNewIndex[fromOld];
        unsigned int toNew   = oldToNewIndex[toOld];

        if (terminals.count(symbol)) {
            ACTION[fromNew][symbol] = Action{Action::SHIFT, (int)toNew};
        } else {
            GOTO[fromNew][symbol] = toNew;
        }
    }

    for (unsigned int i = 0; i < FinalStates.size(); i++) {
        const namedState& state = FinalStates[i];
        
        for (const StateProduction& production : state.state) {
            if (!production.body.empty() && production.body.back() == ".") {
                
                if (production.head == startHead) {
                    for (const string& s : production.lookahead) {
                        if (s == "$") {
                            ACTION[i][s] = Action{Action::ACCEPT};
                        }
                    }
                    continue; 
                }

                vector<string> bodyNoDot(production.body.begin(), production.body.end()-1);
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
                    for (const string& s : production.lookahead) {
                        bool skip = false;

                        if (ACTION[i].count(s)) {
                            const Action& existing = ACTION[i][s];
                            
                            if (existing.type == Action::SHIFT) {
                                skip = true; 
                            } 
                            else if (existing.type == Action::REDUCE) {
                                if (existing.prod.head != originalProd.head || existing.prod.body != originalProd.body) {
                                    cerr << "CRITICAL WARNING: Reduce/Reduce conflict in State " << i 
                                              << " on symbol '" << s << "'.\n"
                                              << "  Existing: " << existing.prod.head << " -> ...\n"
                                              << "  New:      " << originalProd.head << " -> ...\n";
                                    skip = true; 
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

    cout << "===== ACTION TABLE =====\n\n";
    for (int state = 0; state < ACTION.size(); state++) {
        cout << "State " << state << ":\n";
        if (ACTION[state].empty()) {
            cout << "   (no actions)\n\n";
            continue;
        }
        for (const auto& [symbol, act] : ACTION[state]) {
            cout << "   ACTION[" << state << "][" << symbol << "] = ";
            switch (act.type) {
                case Action::SHIFT:  cout << "shift " << act.nexState; break;
                case Action::REDUCE: cout << "reduce " << act.prod.head << " -> ..."; break;
                case Action::ACCEPT: cout << "accept"; break;
                default: cout << "error"; break;
            }
            cout << "\n";
        }
        cout << "\n";
    }
}

void CFG::saveTableToJSON(const string& filename) {
    json root;
    
    for (int i = 0; i < ACTION.size(); i++) {
        for (auto const& [symbol, action] : ACTION[i]) {
            string stateStr = to_string(i);
            
            json actionObj;
            
            if (action.type == Action::SHIFT) {
                actionObj["type"] = "SHIFT";
                actionObj["state"] = action.nexState;
            } 
            else if (action.type == Action::REDUCE) {
                actionObj["type"] = "REDUCE";
                actionObj["lhs"] = action.prod.head; 
                actionObj["rhs"] = action.prod.body; 
            } 
            else if (action.type == Action::ACCEPT) {
                actionObj["type"] = "ACCEPT";
            }
            
            root["action_table"][stateStr][symbol] = actionObj;
        }
    }

    for (int i = 0; i < GOTO.size(); i++) {
        for (auto const& [nonTerminal, nextState] : GOTO[i]) {
            string stateStr = to_string(i);
            root["goto_table"][stateStr][nonTerminal] = nextState;
        }
    }

    ofstream file(filename);
    file << root.dump(4); 
    cout << "Parse table saved to " << filename << endl;
}