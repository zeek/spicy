// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <vector>

#include <hilti/ast/node-ref.h>

namespace hilti::visitor {

/** Represents the location of a single node inside an AST during iteration. */
template<typename E>
class Location {
public:
    E operator*() const { return node; }
    typename std::remove_reference<E>::type* operator->() const { return &node; }

    // private: // TODO: friend doesn't work?
    // friend class Iterator<Erased, order, isConst>;
    Location(E node = nullptr, int child = 0) : node(node), child(child) {}
    E node;
    int child;
};

/** Represents the path to a node inside an AST during iteration. */
template<typename E>
struct Position {
public:
    using Erased = typename std::decay<E>::type;

    /** Node the position refers to. */
    E node;

    /**
     * Path to reach the node. The node itself is the last element inside the
     * path.
     */
    const std::vector<Location<E>>& path;

    /**
     * Returns the length of the AST path to the current node if we're indeed
     * traversing an AST. If we're just dispatching a single node, this will
     * return zero.
     */
    auto pathLength() const { return path.size(); }

    /**
     * Returns a parent.
     *
     * @param parent_nr number of the parent to return; 1 returns immediate parent, 2 the 2nd, etc.
     * @exception `std::out_of_range` if the requested parent does not exist
     */
    E parent(unsigned int parent_nr = 1) const { // 1st parent == 1
        if ( path.size() < 1 + parent_nr )
            throw std::out_of_range("node does not have requested parent");

        return (**(path.end() - 1 - parent_nr));
    }

    /** Returns the first parent that has a given type. */
    template<typename T>
    std::optional<std::reference_wrapper<const T>> findParent() const {
        for ( auto i = path.rbegin() + 1; i != path.rend(); i++ ) {
            if ( (**i).template isA<T>() )
                return {(**i).template as<T>()};
        }

        return std::nullopt;
    }

    /** Returns a reference to the first parent that has a given type. */
    template<typename T>
    NodeRef findParentRef() const {
        for ( auto i = path.rbegin() + 1; i != path.rend(); i++ ) {
            if ( (**i).template isA<T>() )
                return NodeRef(**i);
        }

        return {};
    }
};

} // namespace hilti::visitor
