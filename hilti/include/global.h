// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/ast/node_ref.h>
#include <hilti/ast/type.h>
#include <hilti/base/logger.h>
#include <hilti/base/visitor-types.h>

namespace hilti {

/**
 * Parses a HILTI source file into an AST.
 *
 * @param in stream to read from
 * @param filename path associated with the input
 *
 * Returns: The parsed AST, or a corresponding error if parsing failed.
 */
Result<Node> parseSource(std::istream& in, const std::string& filename);

/**
 * Prints out a debug representation of an AST node to a debug stream. The
 * output will include all the node's children recursively.
 *
 * @param out stream to print to
 * @param node the node
 * @param include_scopes if true, include a dump of each node's identifier
 *        scope
 */
extern void render(std::ostream& out, const Node& node, bool include_scopes = false);

/**
 * Log a debug representation of an AST node to a debug stream. The output
 * will include all the node's children recursively.
 *
 * @param stream stream to log on
 * @param node the node
 * @param include_scopes if true, include a dump of each node's identifier
 *        scope
 */
extern void render(logging::DebugStream stream, const Node& node, bool include_scopes = false);

/**
 * Print out an AST node as HILTI source.
 *
 * @note Usually, this function should be used on an AST's root node (i.e.,
 * the module). The function accepts other nodes, but may not always produce
 * currect code for them.
 *
 * @param out stream to print to
 * @param node the node
 * @param compact if true, print a compact one-line representation (e.g., for
 *        use in error messages)
 */
inline void print(std::ostream& out, const Node& node, bool compact = false) { node.print(out, compact); }

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
 * @return node if resolved, or an appropiate error if not
 */
template<typename D>
Result<std::pair<NodeRef, ID>> lookupID(const ID& id, const visitor::Position<Node&>& p) {
    auto i = p.path.rbegin();
    while ( i != p.path.rend() ) {
        auto [stop, resolved] = detail::lookupID(id, **i);

        if ( ! stop ) {
            if ( auto t = (*i)->tryAs<Type>(); t && t->hasFlag(type::Flag::NoInheritScope) ) {
                // Advance to module scope directly.
                while ( ++i != p.path.rend() ) {
                    if ( (*i)->isA<Module>() )
                        break;
                }
            }
            else
                ++i;

            continue;
        }

        if ( ! resolved )
            return std::move(resolved);

        if ( auto d = (*resolved).first->tryAs<D>() ) {
            if ( ! resolved->second.namespace_() ) {
                // If it's from module's scope, qualify the ID.
                if ( auto m = (*i)->tryAs<Module>() )
                    return std::make_pair(resolved->first, ID(m->id(), resolved->second));
            }

            return std::move(resolved);
        }

        return result::Error(util::fmt("ID '%s' does not resolve to a %s (but to %s)", id, typeid(D).name(),
                                       (*resolved).first->as<Declaration>().displayName()));
    }

    return result::Error(util::fmt("unknown ID '%s'", id));
}


} // namespace hilti
