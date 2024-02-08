// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ast-context.h>
#include <hilti/ast/operator-registry.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using namespace hilti::context;

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
inline const DebugStream AstCache("ast-cache");
} // namespace hilti::logging::debug

Result<Nothing> Options::parseDebugAddl(const std::string& flags) {
    for ( auto i : util::split(flags, ",") ) {
        i = util::trim(i);

        if ( i.empty() )
            continue;
        else if ( i == "trace" )
            debug_trace = true;
        else if ( i == "flow" )
            debug_flow = true;
        else
            return result::Error(
                util::fmt("unknow codegen debug option '%s', must be 'flow' or 'trace' or 'location'", i));
    }

    return Nothing();
}

void Options::print(std::ostream& out) const {
    auto print_one = [&](const char* label, const auto& x) { out << util::fmt("  %25s   %s", label, x) << std::endl; };
    auto print_list = [&](const char* label, const auto& x) {
        if ( x.empty() )
            out << util::fmt("  %25s   <empty>\n", label);
        else {
            bool first = true;
            for ( const auto& i : x ) {
                out << util::fmt("  %25s   %s\n", (first ? label : ""), i);
                first = false;
            }
        }
    };

    out << "\n=== HILTI compiler settings:\n\n";
    print_one("debug", debug);
    print_one("debug_trace", debug_trace);
    print_one("debug_flow", debug_flow);
    print_one("track_location", track_location);
    print_one("skip_validation", skip_validation);
    print_list("addl library_paths", library_paths);
    print_one("cxx_namespace_extern", cxx_namespace_extern);
    print_one("cxx_namespace_intern", cxx_namespace_intern);
    print_list("addl cxx_include_paths", cxx_include_paths);

    out << "\n";
}

Context::Context(Options options)
    : _options(std::move(std::move(options))), _ast_context(std::make_shared<ASTContext>(this)) {}

Context::~Context() {}
