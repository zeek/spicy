// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <hilti/ast/forward.h>

namespace hilti {

class Declaration;
class ID;

/**
 * Scope mapping a set of identifiers to target declarations. An identifier can
 * be mapped to more than one target.
 */
class Scope {
public:
    Scope() = default;
    ~Scope() = default;

    /**
     * Inserts a declaration into the scope.
     *
     * @param d declaration to insert
     * @return true if the insertion changed the scope (vs. having already
     * existed in there before)
     */
    bool insert(Declaration* d);

    /**
     * Inserts a declaration into it's scope under a given ID.
     *
     * @param id ID to insert the declaration under, which does not need to match the declaration's own ID
     * @param d declaration to insert
     * @return true if the insertion changed the scope (vs. having already
     * existed in there before)
     */
    bool insert(const ID& id, Declaration* d);

    /**
     * Inserts a place-holder into the scope that let's lookup fail here if it
     * would normally return that ID.
     *
     * @param id ID to insert the place-holder under
     * @return true if the insertion changed the scope (vs. having already
     * existed in there before)
     */
    bool insertNotFound(const ID& id);

    /** Returns if there's at least one mapping for an ID.  */
    bool has(const ID& id) const { return ! _findID(id).empty(); }

    /** Result type for the lookup methods. */
    struct Referee {
        Declaration* node = nullptr; /**< node that ID maps to */
        std::string qualified;       /**< qualified ID with full path used to find it */
        bool external{};             /**< true if found in a different (imported) module  */
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
    void dump(std::ostream& out, const std::string& prefix = "") const;

    std::string print() const;

    Scope(const Scope& other) = delete;
    Scope(Scope&& other) = delete;
    Scope& operator=(const Scope& other) = delete;
    Scope& operator=(Scope&& other) = delete;

private:
    using ItemMap = std::map<std::string, std::unordered_set<Declaration*>>;

    std::vector<Referee> _findID(const ID& id, bool external = false) const;
    std::vector<Referee> _findID(const Scope* scope, const ID& id, bool external = false) const;

    ItemMap _items;
};

} // namespace hilti
