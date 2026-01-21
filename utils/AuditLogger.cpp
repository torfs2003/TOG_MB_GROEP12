//
// Created by Seher Goker on 13/01/2026.
//

#include "AuditLogger.h"
#include <fstream>

AuditLogger::AuditLogger(const string &LogFile) : m_logFile(LogFile) {}

std::string AuditLogger::nowTimestamp() const {
    time_t now = time(nullptr);
    return sanitize(string(ctime(&now)));
}

std::string AuditLogger::sanitize(const std::string& s) const {
    std::string result;
    for (char c : s) {
        if (c == '\n' || c == '\r' || c == '\t') {
            result += ' ';
        } else {
            result += c;
        }
    }
    return result;
}

void AuditLogger::log(const std::string& queryId,
                      const std::string& role,
                      const std::string& action,
                      const std::string& reason,
                      const std::string& query) {

    // Open logbestand in append-modus
    std::ofstream out(m_logFile, std::ios::app);
    if (!out) {
        // Als loggen faalt, stoppen we stilletjes (geen crash)
        return;
    }


//    if(action == "BLOCKED"){
//        out << nowTimestamp() << " | "
//            << queryId << " | "
//            << role << " | "
//            << /"BLOCKED" << " | "
//            << reason << " | "
//            << sanitize(query)
//            << "\n";
//    }

    out << nowTimestamp() << " | "
        << queryId << " | "
        << role << " | "
        << action << " | "
        << reason << " | "
        << sanitize(query)
        << "\n";
}

