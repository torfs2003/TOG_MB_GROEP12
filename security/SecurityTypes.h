#ifndef SECURITYTYPES_H
#define SECURITYTYPES_H

// DDL - ALLEEN ADMIN
inline const std::unordered_set<std::string> DDL_KEYWORDS = {
    "T_DROP", "T_TRUNCATE", "T_ALTER", "T_CREATE",
    "T_PROCEDURE", "T_BACKUP", "T_GRANT", "T_REVOKE"
};

// DML - EMPLOYEE & ADMIN
inline const std::unordered_set<std::string> DML_KEYWORDS = {
    "T_INSERT", "T_UPDATE", "T_DELETE"
};

// Functies gebruikt voor MySQL Time-Based Blind SQL Injections
inline const std::unordered_set<std::string> TIME_BASED_FUNCTIONS = {
    "T_SLEEP", "T_BENCHMARK"
};

enum class SqlContext {
    NONE,
    SELECT_LIST,
    FROM,
    WHERE,
    JOIN_ON,
    GROUP_BY,
    HAVING,
    ORDER_BY,
    INSERT_VALUES,
    UPDATE_SET
};

enum AlertSeverity {
    SEV_CRITICAL_HARD_BLOCK,
    SEV_HIGH_RISK,
    SEV_MEDIUM_PRIVILEGE,
    SEV_LOW_SUSPICIOUS
};

struct SecurityFinding {
    AlertSeverity severity;
    std::string message;
};

#endif //SECURITYTYPES_H
