#include "Lexer.h"

#include <algorithm>

#include "Keywords.h"

SimpleLexer::SimpleLexer() : keywords(SQL_KEYWORDS), symbols(SQL_SYMBOLS) {}

std::vector<Token> SimpleLexer::tokenize(std::string input) {
    std::vector<Token> tokens;
    int i = 0;
    while (i < input.length()) {
        char c = input[i];
        if (isspace(c)) { i++; continue; }

        // Skip multiline comments /* ... */
        if (c == '/' && i + 1 < input.length() && input[i+1] == '*') {
            i += 2;
            while (i < input.length()) {
                if (input[i] == '*' && i + 1 < input.length() && input[i+1] == '/') {
                    i += 2;
                    break;
                }
                i++;
            }
            continue;
        }

        // Skip single line comments -- ...
        if (c == '-' && i + 1 < input.length() && input[i+1] == '-') {
            while (i < input.length() && input[i] != '\n') {
                i++;
            }
            continue;
        }

        // Identifiers met dubbele aanhalingstekens ("...")
        if (c == '"') {
            std::string val;
            i++;
            while (i < input.length()) {
                if (input[i] == '"') {
                    if (i + 1 < input.length() && input[i+1] == '"') {
                        val += '"';
                        i += 2;
                    } else {
                        i++;
                        break;
                    }
                } else {
                    val += input[i++];
                }
            }
            tokens.push_back({"T_ID", val});
            continue;
        }

        // Identifiers met Backticks (`)
        if (c == '`') {
            std::string val;
            i++;
            while (i < input.length()) {
                if (input[i] == '`') {
                    if (i + 1 < input.length() && input[i+1] == '`') {
                        val += '`';
                        i += 2;
                    } else {
                        i++;
                        break;
                    }
                } else {
                    val += input[i++];
                }
            }
            tokens.push_back({"T_ID", val});
            continue;
        }


        // Hexadecimale getallen (0x...)
        if (c == '0' && i + 1 < input.length() && (input[i+1] == 'x' || input[i+1] == 'X')) {
            std::string hexStr = "0x";
            i += 2;
            while (i < input.length() && isxdigit(input[i])) {
                hexStr += input[i++];
            }
            tokens.push_back({"T_HEX", hexStr});
            continue;
        }

        // Placeholder (?)
        if (c == '?') {
            tokens.push_back({"T_PLACEHOLDER", "?"});
            i++;
            continue;
        }

        //Tijd Literalen
        if (isdigit(c) && i + 1 < input.length() && input[i+1] == ':') {
            std::string timeStr;
            int k = i; // Hulpcursor
            int colonCount = 0;

            // Scan voor het volledige mogelijke tijdspatroon
            while (k < input.length() && (isdigit(input[k]) || input[k] == ':' || input[k] == '.')) {
                if (input[k] == ':') colonCount++;
                timeStr += input[k++];
            }

            // Alleen tokeniseren en cursor verplaatsen als het een geldige tijdsliteraal is
            if (colonCount >= 2) {
                tokens.push_back({"T_TIME_LITERAL", timeStr});
                i = k; // Hoofdcursor verplaatst
                continue;
            }
        }

        // Getallen
        if (isdigit(c)) {
            std::string num;
            bool isFloat = false;
            while (i < input.length() && (isdigit(input[i]) || input[i] == '.')) {
                if (input[i] == '.') isFloat = true;
                num += input[i++];
            }
            tokens.push_back({isFloat ? "T_FLOAT" : "T_INT", num});
            continue;
        }


        // Identifiers en Keywords
        if (isalpha(c) || c == '_' || c == '@') {
            std::string word;
            while (i < input.length() && (isalnum(input[i]) || input[i] == '_' || input[i] == '@')) {
                word += input[i++];
            }

            std::string upper = word;
            transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

            // Speciale gevallen voor gecombineerde keywords (Multi-word lookahead)
            if (upper == "NOT") {
                int tempI = i;
                while (tempI < input.length() && isspace(input[tempI])) tempI++;

                if (tempI < input.length() && (isalpha(input[tempI]) || input[tempI] == '_')) {
                    std::string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    std::string nextUpper = nextWord;
                    transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

                    if (nextUpper == "IN") {
                        tokens.push_back({"T_NOT_IN", "NOT IN"});
                        i = tempI; continue;
                    }
                    else if (nextUpper == "LIKE") {
                        tokens.push_back({"T_NOT_LIKE", "NOT LIKE"});
                        i = tempI; continue;
                    }
                    else if (nextUpper == "NULL") {
                        tokens.push_back({"T_NOT_NULL", "NOT NULL"});
                        i = tempI; continue;
                    }
                }
            }

            // PRIMARY KEY detectie
            if (upper == "PRIMARY") {
                int tempI = i;
                while (tempI < input.length() && isspace(input[tempI])) tempI++;
                if (tempI < input.length() && (isalpha(input[tempI]) || input[tempI] == '_')) {
                    std::string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    std::string nextUpper = nextWord;
                    transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

                    if (nextUpper == "KEY") {
                        tokens.push_back({"T_PK", "PRIMARY KEY"});
                        i = tempI; continue;
                    }
                }
            }

            // FOREIGN KEY detectie
            if (upper == "FOREIGN") {
                int tempI = i;
                while (tempI < input.length() && isspace(input[tempI])) tempI++;
                if (tempI < input.length() && (isalpha(input[tempI]) || input[tempI] == '_')) {
                    std::string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    std::string nextUpper = nextWord;
                    transform(nextUpper.begin(), nextUpper.end(), nextUpper.begin(), ::toupper);

                    if (nextUpper == "KEY") {
                        tokens.push_back({"T_FK", "FOREIGN KEY"});
                        i = tempI; continue;
                    }
                }
            }

            if (keywords.count(upper)) {
                tokens.push_back({keywords[upper], word});
            } else {
                tokens.push_back({"T_ID", word});
            }
            continue;
        }

        // Single quoted std::strings ('...')
        if (c == '\'') {
            std::string s;
            i++;
            while (i < input.length()) {
                if (input[i] == '\'' && i + 1 < input.length() && input[i+1] == '\'') {
                    s += "'";
                    i += 2;
                }
                else if (input[i] == '\'') {
                    i++;
                    break;
                }
                else {
                    s += input[i++];
                }
            }
            tokens.push_back({"T_STRING", s});
            continue;
        }

        // Symbolen en operators
        if (symbols.count(c) || c == '!' || c == '<' || c == '>' || c == '|') {
            std::string op(1, c);
            bool handled = false;

            if (i + 1 < input.length()) {
                char next = input[i+1];
                if (c == '>' && next == '=') {
                    tokens.push_back({"T_GTE", ">="}); i += 2; handled = true;
                }
                else if (c == '<' && next == '=') {
                    tokens.push_back({"T_LTE", "<="}); i += 2; handled = true;
                }
                else if (c == '<' && next == '>') {
                    tokens.push_back({"T_NEQ", "<>"}); i += 2; handled = true;
                }
                else if (c == '!' && next == '=') {
                    tokens.push_back({"T_NEQ", "!="}); i += 2; handled = true;
                }
                else if (c == '|' && next == '|') {
                    tokens.push_back({"T_CONCAT_OP", "||"}); i += 2; handled = true;
                }
            }

            if (handled) continue;

            // Afhandeling van enkelvoudige symbolen
            if (symbols.count(c)) {
                tokens.push_back({symbols[c], op});
                i++;
                continue;
            }
        }
        i++;
    }
    tokens.push_back({"T_EOF", ""});
    tokens.push_back({"$", ""});
    return tokens;
}
