// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/types/name.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/ast-dumper.h>

using namespace hilti;
using util::fmt;

static void dump(Node* n, std::ostream* out, std::optional<logging::DebugStream> dbg, bool include_scopes) {
    util::timing::Collector _("hilti/dumper");

    auto nodes = visitor::range(visitor::PreOrder(), n, {});
    for ( auto i = nodes.begin(true); i != nodes.end(); ++i ) {
        if ( dbg )
            logger().debugSetIndent(*dbg, i.depth());

        if ( out )
            (*out) << std::string(i.depth() - 1, ' ');

        std::string s;

        if ( *i )
            s = fmt("- %s", (*i)->renderSelf());
        else
            s = "- <empty>";

        if ( out )
            (*out) << s << '\n';

        if ( dbg )
            HILTI_DEBUG(*dbg, s);

        if ( include_scopes && *i && (*i)->scope() ) {
            std::stringstream buffer;
            (*i)->scope()->dump(buffer, "    | ");

            if ( buffer.str().size() ) {
                if ( out )
                    (*out) << buffer.str();

                if ( dbg ) {
                    for ( const auto& line : util::split(buffer.str(), "\n") ) {
                        if ( line.size() )
                            HILTI_DEBUG(*dbg, line);
                    }
                }
            }
        }
    }

    if ( dbg )
        logger().debugSetIndent(*dbg, 0);
}

void detail::ast_dumper::dump(std::ostream& out, Node* node, bool include_scopes) {
    ::dump(node, &out, {}, include_scopes);
}

void detail::ast_dumper::dump(logging::DebugStream stream, Node* node, bool include_scopes) {
    ::dump(node, nullptr, stream, include_scopes);
}
