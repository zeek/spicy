// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <utility>
#include <vector>

#include <hilti/ast/node.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>

namespace hilti::visitor {

/**
 * Represents a path inside an AST from the root node to a node reached
 * during iteration.
 */
template<typename N>
using Path = std::vector<std::reference_wrapper<N>>;

/** Given an AST path, returns the current node. */
template<typename N>
N& current(const Path<N>& path) {
    if ( path.empty() )
        logger().internalError("empty path in visitor");

    return (*(path.end() - 1)).get();
}

/**
 * Given an AST path, returns a parent to the current node.
 *
 * @param path AST path
 * @param parent_nr number of the parent to return; 1 returns immediate parent, 2 the 2nd, etc.
 * @exception `std::out_of_range` if the requested parent does not exist
 */
inline const Node& parent(const Path<const Node>& path, int parent_nr = 1) {
    if ( path.size() < 1 + parent_nr )
        throw std::out_of_range("node does not have requested parent");

    return (*(path.end() - 1 - parent_nr)).get();
}

/**
 * Given an AST path, returns a parent to the current node.
 *
 * @param path AST path
 * @param parent_nr number of the parent to return; 1 returns immediate parent, 2 the 2nd, etc.
 * @exception `std::out_of_range` if the requested parent does not exist
 */
inline Node& parent(const Path<Node>& path, int parent_nr = 1) {
    if ( path.size() < 1 + parent_nr )
        throw std::out_of_range("node does not have requested parent");

    return (*(path.end() - 1 - parent_nr)).get();
}

/**
 * Given an AST path, return the first parent of the current node that has a
 * given type.
 */
template<typename T, IF_NOT_SAME(T, Node)>
std::optional<const T> findParent(const Path<Node>& path) {
    for ( auto i = path.rbegin() + 1; i != path.rend(); i++ ) {
        if ( auto t = (*i).get().tryAs<T>() )
            return std::move(t);
    }

    return {};
}

/**
 * Given an AST path, return the first parent of the current node that has a
 * given type.
 */
template<typename T, IF_NOT_SAME(T, Node)>
std::optional<const T> findParent(const Path<const Node>& path) {
    for ( auto i = path.rbegin() + 1; i != path.rend(); i++ ) {
        if ( auto t = (*i).get().tryAs<T>() )
            return std::move(t);
    }

    return {};
}


} // namespace hilti::visitor
