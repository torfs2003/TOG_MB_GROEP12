#ifndef KEYWORDS_H
#define KEYWORDS_H

#include <string>
#include <unordered_map>

inline const std::unordered_map<std::string, std::string> SQL_KEYWORDS = {
    {"ADD", "T_ADD"}, {"ALL", "T_ALL"}, {"ALTER", "T_ALTER"},
    {"AND", "T_AND"}, {"ANY", "T_ANY"}, {"AS", "T_AS"},
    {"ASC", "T_ASC"}, {"AVG", "T_AVG"}, {"BACKUP", "T_BACKUP"},
    {"BETWEEN", "T_BETWEEN"}, {"BIGINT", "T_BIGINT"}, {"BIT", "T_BIT"},
    {"BLOB", "T_BLOB"}, {"BOOLEAN", "T_BOOLEAN_TYPE"}, {"BY", "T_BY"},
    {"CASE", "T_CASE"}, {"CAST", "T_CAST"}, {"CHAR", "T_CHAR"},
    {"CHECK", "T_CHECK"}, {"COLUMN", "T_COLUMN"}, {"CONSTRAINT", "T_CONSTRAINT"},
    {"CONVERT", "T_CONVERT"}, {"COUNT", "T_COUNT"}, {"CREATE", "T_CREATE"},
    {"CROSS", "T_CROSS"}, {"DATE", "T_DATE"}, {"DATETIME", "T_DATETIME"},
    {"DECIMAL", "T_DECIMAL"}, {"DEFAULT", "T_DEFAULT"}, {"DELETE", "T_DELETE"},
    {"CASCADE", "T_CASCADE"}, {"RESTRICT", "T_RESTRICT"}, {"DEFERRABLE", "T_DEFERRABLE"},
    {"ACTION", "T_ACTION"}, {"NO", "T_NO"}, {"DESC", "T_DESC"},
    {"DISTINCT", "T_DISTINCT"}, {"DROP", "T_DROP"}, {"ELSE", "T_ELSE"},
    {"BEGIN", "T_BEGIN"}, {"END", "T_END"}, {"EXCEPT", "T_EXCEPT"},
    {"EXISTS", "T_EXISTS"}, {"FALSE", "T_BOOLEAN"}, {"FLOAT", "T_FLOAT_TYPE"},
    {"GRANT", "T_GRANT"}, {"REVOKE", "T_REVOKE"}, {"TO", "T_TO"},
    {"WAITFOR", "T_WAITFOR"}, {"DELAY", "T_DELAY"}, {"SLEEP", "T_SLEEP"},
    {"BENCHMARK", "T_BENCHMARK"}, {"XOR", "T_XOR"}, {"FROM", "T_FROM"},
    {"FULL", "T_FJOIN"}, {"GROUP", "T_GROUP"}, {"HAVING", "T_HAVING"},
    {"IN", "T_IN"}, {"INDEX", "T_INDEX"}, {"INNER", "T_INNER"},
    {"INSERT", "T_INSERT"}, {"INT", "T_INT_TYPE"}, {"UUID", "T_UUID"},
    {"BYTEA", "T_BYTEA"}, {"INTERVAL", "T_INTERVAL"}, {"GEOMETRY", "T_GEOMETRY"},
    {"MONEY", "T_MONEY"}, {"SMALLINT", "T_SMALLINT"}, {"INTEGER", "T_INTEGER"},
    {"INTERSECT", "T_INTERSECT"}, {"INTO", "T_INTO"}, {"IS", "T_IS"},
    {"JOIN", "T_JOIN"}, {"JSON", "T_JSON"}, {"LEFT", "T_LJOIN"},
    {"LIKE", "T_LIKE"}, {"MAX", "T_MAX"}, {"MIN", "T_MIN"},
    {"MINUS", "T_MINUS_KEYWORD"}, {"NATURAL", "T_NATURAL"}, {"NOT", "T_NOT"},
    {"NULL", "T_NULL"}, {"UNBOUNDED", "T_UNBOUNDED"}, {"NUMERIC", "T_NUMERIC"},
    {"ON", "T_ON"}, {"OR", "T_OR"}, {"ORDER", "T_ORDER"},
    {"OVER", "T_OVER"}, {"PARTITION", "T_PARTITION"}, {"PERCENT", "T_PERCENT"},
    {"PROCEDURE", "T_PROCEDURE"}, {"RANK", "T_RANK"}, {"REAL", "T_REAL"},
    {"REFERENCES", "T_REFERENCES"}, {"RIGHT", "T_RJOIN"}, {"ROW", "T_ROW"},
    {"ROWS", "T_ROWS"}, {"RANGE", "T_RANGE"}, {"ROW_NUMBER", "T_ROW_NUMBER"},
    {"SELECT", "T_SELECT"}, {"SET", "T_SET"}, {"SOME", "T_SOME"},
    {"STRING", "T_STRING_TYPE"}, {"SUM", "T_SUM"}, {"TABLE", "T_TABLE"},
    {"TEXT", "T_TEXT"}, {"THEN", "T_THEN"}, {"TIME", "T_TIME"},
    {"TIMESTAMP", "T_TIMESTAMP"}, {"TINYINT", "T_TINYINT"}, {"TOP", "T_TOP"},
    {"LIMIT", "T_LIMIT"}, {"OFFSET", "T_OFFSET"}, {"TRUNCATE", "T_TRUNCATE"},
    {"TRUE", "T_BOOLEAN"}, {"UNION", "T_UNION"}, {"UNIQUE", "T_UNIQUE"},
    {"UPDATE", "T_UPDATE"}, {"USING", "T_USING"}, {"VALUES", "T_VALUES"},
    {"VARCHAR", "T_VARCHAR"}, {"VIEW", "T_VIEW"}, {"WHEN", "T_WHEN"},
    {"WHERE", "T_WHERE"}, {"WITH", "T_WITH"}, {"XML", "T_XML"},
    {"YEAR", "T_YEAR"}, {"AUTOINCREMENT", "T_AUTOINCREMENT"},
    {"CURRENT_TIMESTAMP", "T_DEFAULT"}, {"CURRENT", "T_CURRENT"},
    {"FOLLOWING", "T_FOLLOWING"}, {"PRECEDING", "T_PRECEDING"},
    {"OUTER", "T_OUTER"}, {"IF", "T_IF"}
};

inline const std::unordered_map<char, std::string> SQL_SYMBOLS = {
    {'*', "T_STAR"}, {',', "T_COMMA"}, {';', "T_PCOMMA"},
    {'(', "T_LPAREN"}, {')', "T_RPAREN"}, {'=', "T_EQ"},
    {'+', "T_ADD"}, {'.', "T_DOT"}, {'>', "T_GT"},
    {'<', "T_LT"}, {'-', "T_MINUS"}, {'/', "T_DIVIDE"},
    {'%', "T_PERCENT"}, {'^', "T_CARET"}, {'&', "T_AMP"},
    {'|', "T_PIPE"}
};

#endif //KEYWORDS_H
