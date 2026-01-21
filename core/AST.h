#ifndef AST_H
#define AST_H
#include <string>
#include <utility>
#include <vector>
#include <iostream>
#include "Token.h"
#include <map>
#include "DotGlobals.h"
#include <fstream>

using namespace std;

struct ASTNode {
    std::string type;
    std::string value;
    int id=0;
    string id2;
    string dotid;
    bool isTainted = false;
    std::vector<ASTNode*> children;


    explicit ASTNode(const Token& token)
        : type(token.type), value(token.value)  {

    }

    explicit ASTNode(std::string  t, std::string  val, const std::vector<ASTNode*>& ch = {})
        : type(std::move(t)), value(std::move(val)), children(ch) {}

    void print(int indent = 0) const {
        std::string pad(indent * 2, ' ');
        std::cout << pad << type;
        if (!value.empty()) std::cout << " (" << value  << ")";
        if (isTainted) std::cout << " [TAINTED]";
        std::cout << "\n";
        for (auto* child : children) {
            if (child) child->print(indent + 1);
        }
    }


//    void dot( ) const {
//        std::string in( 2, ' ');
//        std::string pad = "digraph AST {\n   node [shape=box];\n";
//        pad +=  in ;
//
//
//        //std::cout << pad << type << std::endl;
//
//        doorlopen()
//
//        // we gaan laag per laag
//
//
//
//
//    }








    void doorlopen(ASTNode* node, int queryID, string rolname) const{


        string fileName = "../dot/" + rolname + "_" + to_string(queryID) + "_ast.dot" ;
        //cout << fileName <<endl;

        std::ofstream out(fileName, std::ios::out | std::ios::trunc);


        std::string in( 2, ' ');
        std::string pad = "digraph AST" + to_string(queryID) +" {\n  node [shape=box];\n";



        out << pad << endl;

        node->id2 = "n" + to_string(a);
        node->dotid = node->id2 + " " + "[label=\"" + node->type;
        node->dotid += "\"];\n\n";
        a++;
        if (node) {
            rec(node, fileName);
        }


        node->print_pijlen(fileName);
        pijlen.clear();
    }




    void rec(ASTNode* parent, string fileName) const{

        std::ofstream out(fileName, std::ios::app);



        if (!parent) {
            return;
        }






        out << "  " <<parent->dotid<< endl;

        for (auto child: parent->children) {
            child->id = a;
            child->id2 = "n" + to_string(a);



            child->dotid = child->id2 + " " + "[label=\"" + child->type;
            pijlen[parent->id2].push_back(child->id2);

            if ((child->value).empty()){

                if (child->isTainted){
                    child->dotid += "\", color=red, fontcolor=red, style=filled, fillcolor=mistyrose];\n\n";
                } else{
                    child->dotid += "\"];\n\n";
                }


            } else{
                child->dotid +=  "\\n(" + child->value + ")\"";
                if (child->isTainted) {
                    child->dotid += ", color=red, fontcolor=red, style=filled, fillcolor=mistyrose" ;
                }
                child->dotid += "];";
            }


            a++;
            rec(child, fileName);


        }
    }


    void print_pijlen(string fileName){
        std::ofstream out(fileName, std::ios::app);
        out << "\n" << endl;

        for (auto &i: pijlen){

            for (auto u: i.second) {
                out << "  " << i.first << " -> " << u << ";"<< endl;

            }

        }

        out << "}" ;



    }



};










//std::string ASTNode::dot(int indent ) const {
//
//    std::string pad(indent * 2, ' ');
//    std::cout << pad << std::endl;
//    return pad;
//}

#endif //AST_H
