//
// Created by Seher Goker on 15/01/2026.
//

#include "SchemaSensitiveDetector.h"

SchemaSensitiveDetector::SchemaSensitiveDetector(ASTNode *ast) {


    if (ast) {
        recursive(ast);
    }
}

    void SchemaSensitiveDetector::recursive(ASTNode *parent) {

        if (!parent) {
            return;
        }

        if (parent->type == "table_factor") {
            for (auto child: parent->children) {
                if (child->type == "T_ID") {
                    for (auto &i: warning) {
                        //transform(child->value.begin(), child->value.end(), child->value.begin(), ::tolower);
                        if (child->value.find(i) == 0) {
                            schema_sniffing = true;
                            cout << "schema_sniffing DETECTED  " << endl;
                        }
                    }


                }

            }
        }


        for (auto child: parent->children) {
            recursive(child);
        }


    }
