#include "Lexer.h"
#include "Keywords.h"

SimpleLexer::SimpleLexer() : keywords(SQL_KEYWORDS), symbols(SQL_SYMBOLS) {}

vector<Token> SimpleLexer::tokenize(string input) {
    vector<Token> tokens;
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
            string val;
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
            string val;
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
            string hexStr = "0x";
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

        //  Tijd Literalen
        bool isTimeStart = false;
        if (isdigit(c)) {
            // Check voor H:MM
            if (i + 1 < input.length() && input[i+1] == ':') {
                isTimeStart = true;
            }
            // Check voor HH:MM
            else if (i + 2 < input.length() && isdigit(input[i+1]) && input[i+2] == ':') {
                isTimeStart = true;
            }
        }

        if (isTimeStart) {
            string timeStr;
            int k = i;
            int colonCount = 0;
            
            // Scan voor het volledige mogelijke tijdspatroon
            while (k < input.length() && (isdigit(input[k]) || input[k] == ':' || input[k] == '.')) {
                if (input[k] == ':') colonCount++;
                timeStr += input[k++];
            }
            
            char last = timeStr.back();
            if (colonCount >= 1 && last != ':' && last != '.') { 
                tokens.push_back({"T_TIME_LITERAL", timeStr});
                i = k;
                continue;
            }
        }

        // Getallen
        bool isNumberStart = isdigit(c);
        if (!isNumberStart && (c == '+' || c == '-') && i + 1 < input.length() && isdigit(input[i+1])) {
             isNumberStart = true;
        }

        if (isNumberStart) {
            string num;
            bool isFloat = false;
            
            if (c == '+' || c == '-') {
                num += c;
                i++;
            }

            while (i < input.length()) {
                char next = input[i];
                
                if (isdigit(next)) {
                    num += next;
                    i++;
                } 
                else if (next == '.') {
                    isFloat = true;
                    num += next;
                    i++;
                }
                // Scientific Notation (E-notatie)
                else if (next == 'e' || next == 'E') {
                    isFloat = true;
                    num += next;
                    i++;
                    if (i < input.length() && (input[i] == '+' || input[i] == '-')) {
                        num += input[i++];
                    }
                } 
                else {
                    break;
                }
            }
            tokens.push_back({isFloat ? "T_FLOAT" : "T_INT", num});
            continue;
        }


        // Identifiers en Keywords
        if (isalpha(c) || c == '_' || c == '@') { 
            string word;
            while (i < input.length() && (isalnum(input[i]) || input[i] == '_' || input[i] == '@')) {
                word += input[i++];
            }
            
            string upper = word;
            transform(upper.begin(), upper.end(), upper.begin(), ::toupper);

            // Speciale gevallen voor gecombineerde keywords (Multi-word lookahead)
            if (upper == "NOT") {
                int tempI = i;
                while (tempI < input.length() && isspace(input[tempI])) tempI++;

                if (tempI < input.length() && (isalpha(input[tempI]) || input[tempI] == '_')) {
                    string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    string nextUpper = nextWord;
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
                    string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    string nextUpper = nextWord;
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
                    string nextWord;
                    while (tempI < input.length() && (isalnum(input[tempI]) || input[tempI] == '_')) {
                        nextWord += input[tempI++];
                    }
                    string nextUpper = nextWord;
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
        
        // Single quoted strings ('...')
        if (c == '\'') {
            string s;
            i++;
            while (i < input.length()) {
                if (input[i] == '\\' && i + 1 < input.length()) {
                    s += input[i+1];
                    i += 2;
                    continue;
                }
                if (input[i] == '\'') {
                    if (i + 1 < input.length() && input[i+1] == '\'') {
                        s += "'";
                        i += 2;
                    } else {
                        i++; 
                        break;
                    }
                } else {
                    s += input[i++];
                }
            }
            tokens.push_back({"T_STRING", s});
            continue;
        }

        // Symbolen en operators
        if (symbols.count(c) || c == '!' || c == '<' || c == '>' || c == '|') {
            string op(1, c);
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