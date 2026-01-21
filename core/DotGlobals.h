//
// Created by Seher Goker on 18/01/2026.
//

#ifndef LALR_1__PARSER_DOTGLOBALS_H
#define LALR_1__PARSER_DOTGLOBALS_H

#endif //LALR_1__PARSER_DOTGLOBALS_H

#pragma once
#include <map>
#include <string>
#include <vector>

// C++17 inline variable → 1 gedeelde instantie in heel het programma
inline std::map<std::string, std::vector<std::string>> pijlen;
inline int a = 0;