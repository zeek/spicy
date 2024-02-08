// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// clang-based AST extraction helper for `scripts/autogen-builder-api`; see there.

#include <cstdlib>
#include <iostream>
#include <set>

// Declares clang::SyntaxOnlyAction.
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
// Declares llvm::cl::extrahelp.

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "llvm/Support/CommandLine.h"

using namespace clang::tooling;
using namespace llvm;
using namespace clang;
using namespace clang::ast_matchers;

// Apply a custom category to all command-line options so that they are the
// only ones displayed.
static llvm::cl::OptionCategory MyToolCategory("my-tool options");

// CommonOptionsParser declares HelpMessage with a description of the common
// command-line options related to the compilation database and input files.
// It's nice to have this help message in all tools.
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);

// A help message for this specific tool can be added afterwards.
static cl::extrahelp MoreHelp("\nMore help text...\n");

// auto Matcher = cxxMethodDecl(hasName("create")).bind("create");
auto Matcher =
    cxxMemberCallExpr(callee(cxxMethodDecl(anyOf(hasName("isA"), hasName("tryAs"), hasName("as"))))).bind("call");

class Printer : public MatchFinder::MatchCallback {
public:
    Printer(std::vector<std::string> files) : files(std::move(files)) {}
    std::vector<std::string> files;
    std::set<std::string> seen;

    void run(const MatchFinder::MatchResult& Result) override {
        // Print result.
        auto node = Result.Nodes.getNodeAs<CXXMemberCallExpr>("call");
        auto self = node->getImplicitObjectArgument();
        if ( auto x = dyn_cast<ImplicitCastExpr>(self) ) {
            auto expr = x->getSubExpr();
            auto type = expr->getType().getCanonicalType().getAsString();
            if ( type.find("QualifiedType") != std::string::npos ) {
                const auto& mgr = Result.Context->getSourceManager();
                auto loc = expr->getSourceRange().getEnd();
                std::cout << mgr.getFilename(loc).str() << ":" << mgr.getSpellingLineNumber(loc) << ":"
                          << mgr.getExpansionColumnNumber(loc) << ": cast probably broken" << '\n';
            }
        }
    }
};

int main(int argc, const char** argv) {
    auto OptionsParser = CommonOptionsParser::create(argc, argv, MyToolCategory);
    if ( ! OptionsParser ) {
        // Fail gracefully for unsupported options.
        llvm::errs() << OptionsParser.takeError();
        return 1;
    }

    ClangTool Tool(OptionsParser->getCompilations(), OptionsParser->getSourcePathList());

    ArgumentsAdjuster Adjuster =
        getInsertArgumentAdjuster({"-x", "c++", "-Wno-pragma-once-outside-header"}, ArgumentInsertPosition::BEGIN);
    Tool.appendArgumentsAdjuster(Adjuster);

    // Save name of source file
    Printer Printer(OptionsParser->getSourcePathList());
    MatchFinder Finder;
    Finder.addMatcher(Matcher, &Printer);

    return Tool.run(newFrontendActionFactory(&Finder).get());
}
