// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
// Functionality factored out from scope.h to avoid header loops.

#pragma once

#include <optional>
#include <string>

#include <hilti/ast/declarations/type.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/ast/node_ref.h>
#include <hilti/ast/type.h>
#include <hilti/base/visitor-types.h>

namespace hilti::scope {

namespace detail {
/** Internal backend to `hilti::lookupID()`. */
extern std::pair<bool, Result<std::pair<NodeRef, ID>>> lookupID(const ID& id, const Node& n);
} // namespace detail

/**
 * Looks up a still unresolved ID inside an AST. The ID is expected to
 * resolve to exactly one declaration of an expected type, and must be
 * exported if inside another module; otherwise an error is flagged.
 *
 * @tparam D class implementing the `Declaration` interface that we expecting the ID to resolve to
 * @param id id to look up
 * @param p AST position where to start the lookup; we'll traverse up the AST from there
 * @param n node to use for error reporting if something goes wrong
 * @return node if resolved, or an appropiate error if not
 */
template<typename D>
Result<std::pair<NodeRef, ID>> lookupID(const ID& id, const visitor::Position<Node&>& p) {
    auto i = p.path.rbegin();
    while ( i != p.path.rend() ) {
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
                return result::Error(util::fmt("ID '%s' does not resolve to a %s (but to %s)", id, typeid(D).name(),
                                               (*resolved).first->as<Declaration>().displayName()));
        }

        if ( stop )
            // Pass back error.
            return std::move(resolved);

        if ( auto t = (*i)->tryAs<Type>(); t && t->hasFlag(type::Flag::NoInheritScope) ) {
            // Advance to module scope directly.
            while ( ++i != p.path.rend() ) {
                if ( (*i)->isA<Module>() )
                    break;
            }
        }
        else
            ++i;
    }

    return result::Error(util::fmt("unknown ID '%s'", id));
}

} // namespace hilti::scope
