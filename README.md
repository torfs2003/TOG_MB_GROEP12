# SQL LALR(1) Parser & Security Analyzer

> **Course:** Machines & Berekenbaarheid  
> **Lecturer:** Prof E. Laenens & T. Hofkens  
> **Language:** C++17  

## Overview

This project is a custom-built SQL parsing engine and security analysis tool. Unlike standard implementations that rely on parser generators like Bison or Yacc, we implemented the entire compilation pipeline from scratch.

This includes defining a custom **Context-Free Grammar (CFG)** for a subset of SQL, implementing a generator for **LALR(1) Parse Tables**, and building a **Security Analyzer** capable of detecting SQL Injection vulnerabilities and enforcing Role-Based Access Control (RBAC).

## Key Features

### 1. Core Parsing Engine
* **Custom CFG Definition:** The SQL grammar is defined manually in `CFG.json`, allowing full control over language rules.
* **LALR(1) Table Generator:** We wrote a dedicated algorithm to calculate First/Follow sets and generate the parsing table (`parsetable.json`) automatically from the CFG.
* **Abstract Syntax Tree (AST):** The parser constructs a hierarchical tree structure of the query, which serves as the foundation for further analysis.

### 2. Security & Analysis
The engine utilizes a multi-layered security approach:

* **Taint Analysis:** Tracks "tainted" data (untrusted user input/placeholders `?`) flowing through the AST.
    * *Critical Risk:* Blocks execution if tainted data reaches dangerous functions (e.g., `SLEEP`).
    * *Warning:* Flags potential injection points in `WHERE` or `JOIN` clauses.
* **Context-Aware Security Scan:** Detects semantic attack patterns:
    * **Tautologies:** Detects logic bypasses like `OR 1=1`, `OR id=id`, or `OR TRUE`.
    * **Structural Violations:** Flags `OR` clauses starting with literals rather than column names.
    * **DoS Prevention:** Blocks time-based attacks using keywords like `SLEEP`.
    * **Schema Enumeration:** Detects and logs attempts to access system tables (`information_schema`).
* **RBAC Firewall:** Simulates a permission system (Admin, Employee, Client) to restrict query types (DDL vs. DML) before execution.

### 3. Visualization
* **Automated Graphing:** Integrates with **Graphviz** to generate `.png` visualizations of the AST for every processed query.
* **Visual Debugging:** Tainted nodes are highlighted in **RED** in the generated images, making security flows easy to trace.

### 4. Audit Logging
To ensure accountability and traceability, the system maintains a persistent `analysis.log` file. Every query processed by the engine is timestamped and recorded with its final verdict.

* **Traceability:** Records the exact time (`Thu Jan 22 12:02:05 2026`), user role (`ADMIN [RWX]`), and query ID.
* **Verdict Tracking:** Clearly distinguishes between `ALLOWED` queries and those `BLOCKED` by the Firewall or Taint Analysis.
* **Reasoning:** Logs the specific security mechanism that triggered the block (e.g., `TAINT`, `FIREWALL`).

**Sample Log Output:**
```text
Thu Jan 22 12:02:05 2026  | ADMIN [RWX] (Full Control / DDL)-3 | ADMIN [RWX] (Full Control / DDL) | BLOCKED | FIREWALL | SELECT * FROM accounts WHERE balance < 100 OR 2>1;
Thu Jan 22 12:02:06 2026  | ADMIN [RWX] (Full Control / DDL)-15 | ADMIN [RWX] (Full Control / DDL) | ALLOWED | OK | SELECT COUNT(*) FROM users GROUP BY role HAVING COUNT(*) > ?;
Thu Jan 22 12:02:06 2026  | ADMIN [RWX] (Full Control / DDL)-16 | ADMIN [RWX] (Full Control / DDL) | BLOCKED | TAINT | SELECT * FROM users WHERE id = SLEEP(?);
```
---

## Architecture Pipeline

The application processes a query through the following stages:

1.  **Authentication:** User logs in via the console; the system retrieves the role from `user.json`.
2.  **Grammar Loading:** Reads production rules from `CFG.json`.
3.  **Table Generation:** Generates the LALR(1) state machine (exported to `parsetable.json`).
4.  **Lexing & Parsing:** Converts raw SQL into tokens and builds the AST.
5.  **Semantic Analysis:**
    * Validates syntax and RBAC permissions.
    * Performs Taint Analysis and Security Scanning.
6.  **Reporting:** Outputs a detailed security report to the console and generates visual graphs in the `dot/` folder.

---

## Prerequisites

* **C++ Compiler:** Supporting C++17 or higher
* **CMake:** Version 3.10+
* **Graphviz:** Required for AST visualization
    * *Windows:* Install Graphviz and add `bin/` to system PATH.
    * *macOS:* `brew install graphviz`
    * *Linux:* `sudo apt-get install graphviz`

## Configuration Files

| File | Description |
| :--- | :--- |
| `CFG.json` | The Context-Free Grammar rules for our SQL subset. |
| `parsetable.json` | The generated LALR(1) parsing table (auto-generated). |
| `user.json` | Database of users, passwords, and roles for RBAC testing. |
| `query.json` | A list of SQL queries to run through the validator. |

---

## Authors
Döne Göker

Lasse Torfsa

Chakkarin Van Noten

Ruben Wuyts