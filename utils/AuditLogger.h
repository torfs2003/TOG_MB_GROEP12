//
// Created by Seher Goker on 13/01/2026.
//
#include <iostream>
#pragma once

using namespace std;
#ifndef LALR_1__PARSER_AUDITLOGGER_H
#define LALR_1__PARSER_AUDITLOGGER_H


class AuditLogger {

public:
    // maak logger die naar analysis.log schrijft
    // de constructor
    explicit AuditLogger(const string& LogFile);


    // schrijf een log per query
    void log(const string& queryID,
             const string& role,
             const string& action,
             const string& reason,
             const std::string& query
            );

private:
    std::string m_logFile;
    std::string nowTimestamp() const;
    std::string sanitize(const std::string& s) const;




};


#endif //LALR_1__PARSER_AUDITLOGGER_H
