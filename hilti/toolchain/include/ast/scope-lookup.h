// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// Functionality factored out from scope.h to avoid header loops.

#pragma once

#include <memory>
#include <optional>
#include <utility>

#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/base/logger.h>

namespace hilti::scope {
namespace detail {
/** Internal backend to `hilti::lookupID()`. */
std::pair<bool, Result<std::pair<Declaration*, ID>>> lookupID(const ID& id, const Node* n);
} // namespace detail

/**
 * Looks up a still unresolved ID inside an AST. The ID is expected to
 * resolve to exactly one declaration of an expected type, and must be
 * exported if inside another module; otherwise an error is flagged.
 *
 * @tparam D class implementing the `Declaration` interface that we expecting the ID to resolve to
 * @param id id to look up
 * @param n AST position where to start the lookup; we'll traverse up the AST from there
 * @param what textual description of what we're looking for (i.e., of *D*); used in error messages
 * @return node if resolved, or an appropriate error if not
 */
template<typename D>
Result<std::pair<D*, ID>> lookupID(ID id, Node* n, const std::string_view& what) {
    if ( id.empty() )
        logger().internalError("lookupID() called with empty ID");

    while ( n ) {
        auto [stop, resolved] = detail::lookupID(id, n);
        if ( resolved ) {
            if ( ! resolved->first )
                // null pointer means a forced not found.
                return result::Error(util::fmt("ID '%s' not found", id));

            if ( auto d = resolved->first->tryAs<D>() )
                return std::make_pair(d, resolved->second);
            else
                return result::Error(util::fmt("ID '%s' does not resolve to a %s (but to a %s)", id, what,
                                               (*resolved).first->displayName()));
        }

        if ( stop )
            // Pass back error.
            return resolved.error();

        bool skip_to_module = false;
        bool skip_to_root = false;

        // Let "::<ID>" skip to module scope directly.
        if ( id.length() > 1 && id.sub(0).empty() ) {
            skip_to_module = true;
            id = id.sub(1, -1);
        }

        // Let "~<ID>" skip to root scope directly. This is for internal use of
        // IDs accessible there through standard imports.
        if ( util::startsWith(id.str(), "~") ) {
            skip_to_root = true;
            id = ID(id.str().substr(1));
        }

        // If the node does not have the inheritScope flag, we skip everything
        // else in remainder of the path except for the top-level module, to
        // which we then jump directly. One exception: If the node is part of a
        // type declaration, we need to check the declaration's scope still as
        // well; that's the "if" clause below allowing to go one further step
        // up, and the "else" clause then stopping during the next round.
        if ( auto t = n->tryAs<UnqualifiedType>(); t && ! t->inheritScope() ) {
            if ( n->parent() && n->parent()->tryAs<declaration::Type>() )
                // Ignore, we'll cover this in next round in the case below.
                continue;

            skip_to_module = true;
        }
        else if ( auto t = n->tryAs<declaration::Type>(); t && ! t->type()->inheritScope() )
            skip_to_module = true;

        if ( skip_to_module ) {
            // Advance to module scope directly.
            while ( (n = n->parent()) ) {
                if ( n->isA<declaration::Module>() )
                    break;
            }
        }
        else if ( skip_to_root ) {
            // Advance to root scope directly.
            n = n->parent<ASTRoot>();
            assert(n);
        }
        else {
            if ( n->isA<declaration::Module>() )
                // Don't go beyond module scope (i.e., don't go into the root node)
                // This avoids finding implicit system imports.
                break;

            n = n->parent();
        }
    }

    return result::Error(util::fmt("unknown ID '%s'", id));
}
} // namespace hilti::scope
