// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/node-ref.h>
#include <hilti/base/intrusive-ptr.h>

namespace hilti {

class Declaration;
class ID;

/**
 * Identifier scope. A scope maps identifiers to AST nodes (more precisely: to
 * references to AST nodes). An identifier can be mapped to more than one node.
 */
class Scope : public intrusive_ptr::ManagedObject {
public:
    Scope() = default;
    ~Scope() = default;

    void insert(NodeRef&& n);
    void insert(const ID& id, NodeRef&& n);
    void insertNotFound(const ID& id);

    /** Returns if there's at least one mapping for an ID.  */
    bool has(const ID& id) const { return ! _findID(id).empty(); }

    /** Result typer for the lookup methods. */
    struct Referee {
        NodeRef node;          /**< node that ID maps to */
        std::string qualified; /**< qualified ID with full path used to find it */
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
    // Specialized implementation for `NodeRef` hashing and equality checks for
    // nodes referencing declarations.
    struct NodeRefHash {
        std::size_t operator()(const hilti::NodeRef& n) const;
    };

    struct NodeRefEqual {
        bool operator()(const hilti::NodeRef& a, const hilti::NodeRef& b) const;
    };

    using ItemMap = std::map<std::string, std::unordered_set<NodeRef, NodeRefHash, NodeRefEqual>>;

    std::vector<Referee> _findID(const ID& id, bool external = false) const;
    std::vector<Referee> _findID(const Scope* scope, const ID& id, bool external = false) const;

    ItemMap _items;
};

} // namespace hilti
