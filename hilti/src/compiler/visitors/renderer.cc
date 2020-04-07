// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/types/id.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;
using util::fmt;

static void render(const Node& n, std::ostream* out, std::optional<logging::DebugStream> dbg, bool include_scopes) {
    util::timing::Collector _("hilti/renderer");

    int dbg_level = 0;

    for ( const auto& i : visitor::PreOrder<>().walk(n) ) {
        int new_dbg_level = i.path.size();

        while ( dbg_level < new_dbg_level ) {
            logger().debugPushIndent(*dbg);
            dbg_level++;
        }

        while ( dbg_level > new_dbg_level ) {
            logger().debugPopIndent(*dbg);
            dbg_level--;
        }

#if 0
        // Condense AST output, struct types can be very long.
        if ( i.findParent<type::Struct>() )
            continue;
#endif

        if ( out )
            (*out) << std::string(dbg_level - 1, ' ');

        auto s = fmt("- %s", i.node.render());

        if ( out )
            (*out) << s << '\n';

        if ( dbg )
            HILTI_DEBUG(*dbg, s);

        if ( include_scopes ) {
            std::stringstream buffer;
            i.node.scope()->render(buffer, "    | ");

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

    while ( dbg_level-- > 0 )
        logger().debugPopIndent(*dbg);
}

void detail::renderNode(const Node& n, std::ostream& out, bool include_scopes) {
    ::render(n, &out, {}, include_scopes);
}

void detail::renderNode(const Node& n, logging::DebugStream stream, bool include_scopes) {
    ::render(n, nullptr, stream, include_scopes);
}
