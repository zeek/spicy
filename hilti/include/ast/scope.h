// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <unordered_map>

#include <hilti/ast/node_ref.h>

namespace hilti {

class ID;

/**
 * Identifier scope. A scope maps identifiers to AST nodes (more precisely:
 * to referneces to AST nodes). An identifier can be mapped to more than one
 * node.
 */
class Scope {
public:
    Scope() = default;
    ~Scope() = default;

    /**
     * Inserts a new identifier mapping. If a mapping for the ID already
     * exists, the new one is appended to it.
     *
     * @param id id to map
     * @param n reference to the node that `id` is to be mapped to
     */
    void insert(const ID& id, NodeRef n);

    /**
     * Inserts a new identifier mapping.
     *
     * @param id id to map
     * @param n node to map to; as a scope always maps to *references*,
     *          this takes ownership of the node and stores it internally
     */
    void insert(const ID& id, Node&& n);

    /** Returns true if there's at least one mapping for an ID.  */
    bool has(const ID& id) const { return ! _findID(id).empty(); }

    /** Result typer for the lookup methods. */
    struct Referee {
        NodeRef node;          /**< node that ID maps to */
        std::string qualified; /**< qualified ID with full path used to find it  */
        bool external{};       /**< true if found in a different (imported) module  */
    };

    /** Returns all mappings for an ID. */
    std::vector<Referee> lookupAll(const ID& id) const { return _findID(id); }

    /** Returns first mapping for an ID. */
    std::optional<Referee> lookup(const ID& id) const {
        if ( auto ids = _findID(id); ! ids.empty() )
            return ids.front();

        return {};
    }

    /** Empties the scope. */
    void clear() { _items.clear(); }

    /** Returns all mappings of the scope. */
    const auto& items() const { return _items; }

    /**
     * Copies the scope's mappings into another one.
     */
    void copyInto(Scope* dst) const {
        for ( const auto& i : _items )
            dst->_items.insert(i);
    }

    /**
     * Moves the scope's mappings into another one. The source scope will be
     * empty afterwards.
     */
    void moveInto(Scope* dst) {
        // dst->_items.merge(std::move(_items)); // C++17, not supported by libc++ yet it seems
        for ( const auto& i : _items )
            dst->_items.insert(i);

        _items.clear();
    }

    /**
     * Prints out a debugging representation of the scope's content.
     *
     * @param out stream to print to
     * @param prefix string to prefix each printed scope item with
     */
    void render(std::ostream& out, const std::string& prefix = "") const;

    Scope(const Scope& other) = delete;
    Scope(Scope&& other) = delete;
    Scope& operator=(const Scope& other) = delete;
    Scope& operator=(Scope&& other) = delete;

private:
    using ItemMap = std::map<std::string, std::vector<NodeRef>>;

    std::vector<Referee> _findID(const ID& id, bool external = false) const;
    std::vector<Referee> _findID(const Scope* scope, const ID& id, bool external = false) const;

    ItemMap _items;
    std::vector<std::shared_ptr<Node>> _nodes; // Nodes without other owners.
};

} // namespace hilti
