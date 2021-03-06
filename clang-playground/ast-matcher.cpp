#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory opt_cat("my-tool options");

class OnFnCall: public MatchFinder::MatchCallback {
public:
    virtual void run(const MatchFinder::MatchResult &res) {
        if (const FunctionDecl *fn = res.Nodes.getNodeAs<FunctionDecl>("fn")) {
            SourceLocation loc = fn->getLocation();
            std::cout << fn->getNameAsString() << " " << loc.printToString(*res.SourceManager) << std::endl;
        }
    }
};

int main(int argc, const char **argv) {
    std::ifstream file("files");
    if (!file.is_open()) {
        std::cerr << "failed to open file list" << std::endl;
        return 1;
    }

    std::vector<std::string> vec;
    std::string s;
    while (true) {
        file >> s;
        if (file.eof())
            break;
    }

    CommonOptionsParser opt_parser(argc, argv, opt_cat);
    //ClangTool tool(opt_parser.getCompilations(), opt_parser.getSourcePathList());
    ClangTool tool(opt_parser.getCompilations(), ArrayRef<std::string>(s));

    // Match functions that call function named `f`
    DeclarationMatcher fn_matcher = functionDecl(hasDescendant(callExpr(callee(functionDecl(hasName("f"))))))
        .bind("fn");

    OnFnCall cb;
    MatchFinder finder;
    finder.addMatcher(fn_matcher, &cb);
    return tool.run(newFrontendActionFactory(&finder).get());
    return 0;
}
