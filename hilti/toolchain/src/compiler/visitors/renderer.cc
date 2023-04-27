// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/types/unresolved-id.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;
using util::fmt;

static void render(const Node& n, std::ostream* out, std::optional<logging::DebugStream> dbg, bool include_scopes) {
    util::timing::Collector _("hilti/renderer");

    auto v = visitor::PreOrder<>();
    for ( const auto i : v.walk(n) ) {
        if ( dbg )
            logger().debugSetIndent(*dbg, i.path.size());

        if ( out )
            (*out) << std::string(i.path.size() - 1, ' ');

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

    if ( dbg )
        logger().debugSetIndent(*dbg, 0);
}

void detail::renderNode(const Node& n, std::ostream& out, bool include_scopes) {
    ::render(n, &out, {}, include_scopes);
}

void detail::renderNode(const Node& n, logging::DebugStream stream, bool include_scopes) {
    ::render(n, nullptr, stream, include_scopes);
}
