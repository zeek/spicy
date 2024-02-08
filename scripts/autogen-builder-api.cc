// clang-based AST extraction helper for `scripts/autogen-builder-api`; see there.

#include <cstdlib>
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

std::string replace(std::string s, std::string_view o, std::string_view n) {
    if ( o.empty() )
        return s;

    size_t i = 0;
    while ( (i = s.find(o, i)) != std::string::npos ) {
        s.replace(i, o.length(), n);
        i += n.length();
    }

    return s;
}

// Apply a custom category to all command-line options so that they are the
// only ones displayed.
static llvm::cl::OptionCategory MyToolCategory("my-tool options");

// CommonOptionsParser declares HelpMessage with a description of the common
// command-line options related to the compilation database and input files.
// It's nice to have this help message in all tools.
static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);

// A help message for this specific tool can be added afterwards.
static cl::extrahelp MoreHelp("\nMore help text...\n");

auto Matcher = cxxMethodDecl(hasName("create")).bind("create");

class Printer : public MatchFinder::MatchCallback {
public:
    Printer(std::vector<std::string> files) : files(std::move(files)) {}
    std::vector<std::string> files;
    std::set<std::string> seen;

    void run(const MatchFinder::MatchResult& Result) override {
        std::string class_;
        std::string full_args;
        std::string arg_names;
        std::string file;
        std::string location;

        if ( auto create = Result.Nodes.getNodeAs<CXXMethodDecl>("create") ) {
            // Ignore if not public.
            if ( create->getAccess() != AS_public )
                return;

            class_ = create->getParent()->getQualifiedNameAsString(); // parent is CxxRecordDecl

            // print source file
            auto loc = create->getBeginLoc();
            file = Result.SourceManager->getFilename(loc);
            location = loc.printToString(*Result.SourceManager);
            if ( std::find(files.begin(), files.end(), file) == files.end() || seen.count(location) )
                return;

            seen.insert(location);

            for ( auto i = 0; i < create->getNumParams(); i++ ) {
                auto param = create->getParamDecl(i);
                auto txt = decl2str(param, Result.SourceManager);

                auto param_name = param->getNameAsString();

                if ( param_name == "ctx" )
                    continue;

                if ( param_name.empty() ) {
                    param_name = "_unused";
                    txt += " _unused";
                }

                if ( full_args.empty() ) {
                    full_args = txt;
                    arg_names = param_name;
                }
                else {
                    full_args += ", " + txt;
                    arg_names += ", " + param_name;
                }
            }
        }


        auto method = class_;
        method = replace(method, "hilti::", "");
        method = replace(method, "spicy::", "");
        method = replace(method, "_::", "::");
        if ( method[method.size() - 1] == '_' )
            method = method.substr(0, method.size() - 1);

        while ( true ) {
            auto i = method.find('_');
            if ( i == std::string::npos )
                break;

            method =
                method.substr(0, i) + std::string(1, static_cast<char>(toupper(method[i + 1]))) + method.substr(i + 2);
        }

        bool first = true;
        std::string::size_type i = 0;
        while ( true ) {
            if ( first )
                method[i] = static_cast<char>(tolower(method[i]));
            else
                method[i] = static_cast<char>(toupper(method[i]));

            first = false;

            i = method.find("::", i);
            if ( i == std::string::npos )
                break;

            i += 2;
            if ( i >= method.size() )
                break;
        }

        method = replace(method, "::", "");
        full_args = replace(full_args, "\n", " ");

        printf("    auto %s(%s) { return %s::create(context(), %s); } // %s\n", method.c_str(), full_args.c_str(),
               class_.c_str(), arg_names.c_str(), location.c_str());
    }

    std::string decl2str(const clang::Decl* d, clang::SourceManager* sm) {
        clang::SourceLocation b(d->getBeginLoc());
        clang::SourceLocation _e(d->getEndLoc());
        clang::SourceLocation e(clang::Lexer::getLocForEndOfToken(_e, 0, *sm, clang::LangOptions{}));

        return std::string(sm->getCharacterData(b), sm->getCharacterData(e) - sm->getCharacterData(b));
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
