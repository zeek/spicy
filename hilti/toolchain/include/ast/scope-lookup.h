// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// Functionality factored out from scope.h to avoid header loops.

#pragma once

#include <optional>
#include <utility>

#include <hilti/ast/declarations/type.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/type.h>
#include <hilti/base/visitor-types.h>

namespace hilti::scope {

namespace detail {
/** Internal backend to `hilti::lookupID()`. */
std::pair<bool, Result<std::pair<NodeRef, ID>>> lookupID(const ID& id, const Node& n);
} // namespace detail

/**
 * Looks up a still unresolved ID inside an AST. The ID is expected to
 * resolve to exactly one declaration of an expected type, and must be
 * exported if inside another module; otherwise an error is flagged.
 *
 * @tparam D class implementing the `Declaration` interface that we expecting the ID to resolve to
 * @param id id to look up
 * @param p AST position where to start the lookup; we'll traverse up the AST from there
 * @param what textual description of what we're looking for (i.e., of *D*); used in error messages
 * @return node if resolved, or an appropriate error if not
 */
template<typename D>
Result<std::pair<NodeRef, ID>> lookupID(const ID& id, const visitor::Position<Node&>& p, const std::string_view& what) {
    if ( ! id )
        logger().internalError("lookupID() called with empty ID");

    for ( auto i = p.path.rbegin(); i != p.path.rend(); ++i ) {
        auto [stop, resolved] = detail::lookupID(id, **i);

        if ( resolved ) {
            if ( auto d = (*resolved).first->tryAs<D>() ) {
                if ( ! resolved->second.namespace_() ) {
                    // If it's from module's scope, qualify the ID.
                    if ( auto m = (*i)->tryAs<Module>() )
                        return std::make_pair(resolved->first, ID(m->id(), resolved->second));
                }

                else
                    return std::move(resolved);
            }
            else
                return result::Error(util::fmt("ID '%s' does not resolve to a %s (but to a %s)", id, what,
                                               (*resolved).first->as<Declaration>().displayName()));
        }

        if ( stop )
            // Pass back error.
            return std::move(resolved);

        // If the type has the NoInheritScope flag, we skip everything else
        // in remainder of the path except for the top-level module, to which
        // we then jump directly. One exception: If the type is part of a
        // type declaration, we need to check the declaration's scope still
        // as well; that's the "if" clause below allowing to go one further
        // step up, and the "else" clause then stopping during the next
        // round.
        bool skip_to_module = false;

        if ( auto t = (*i)->tryAs<Type>(); t && t->hasFlag(type::Flag::NoInheritScope) ) {
            if ( auto x = i; ++x != p.path.rend() && (*x)->tryAs<declaration::Type>() )
                // Ignore, we'll cover this in next round in the case below.
                continue;

            skip_to_module = true;
        }
        else if ( auto t = (*i)->tryAs<declaration::Type>(); t && t->type().hasFlag(type::Flag::NoInheritScope) )
            skip_to_module = true;

        if ( skip_to_module ) {
            // Advance to module scope directly.
            while ( ++i != p.path.rend() ) {
                if ( (*i)->isA<Module>() )
                    break;
            }
            --i; // for-loop will increase
        }
    }

    return result::Error(util::fmt("unknown ID '%s'", id));
}

} // namespace hilti::scope
