// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/location.h>
#include <hilti/base/result.h>

#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen {

class Production;

namespace production {
class Deferred;
} // namespace production

/** A Spicy grammar. Each unit is translated into a grammar for parsing. */
class Grammar {
public:
    /**
     * Instantiates a new grammar that's initially empty. `setRoot` then
     * initializes the grammar with its root production.
     *
     * @param name name associated with the grammar; must be unique, and is used both for debugging
     *             and for generating labels during code generation
     * @param root top-level root production
     * @param l associated location
     */
    Grammar(std::string name, hilti::Location l = hilti::location::None)
        : _name(std::move(name)), _location(std::move(l)) {}
    Grammar() = default;
    Grammar(const Grammar&) = delete;
    Grammar(Grammar&&) = default;
    ~Grammar() = default;
    Grammar& operator=(Grammar&&) = default;
    Grammar& operator=(const Grammar&) = delete;

    /**
     * Returns the name of the grammar. The name uniquely identifies the
     * grammar.
     */
    const std::string& name() const { return _name; }

    /** Returns the location associated with the production. */
    const hilti::Location& location() const { return _location; }

    /**
     * Resolves an previous place-holder production with an actual production.
     * Once resolved, parser table construction will use the actual production
     * everywhere where the place-holder is referenced.
     */
    void resolve(production::Deferred* r, std::unique_ptr<Production> p);

    /** Returns the actual production a resolved production refers to. */
    Production* resolved(const production::Deferred* r) const;

    /**
     * Sets the root production for the grammar. This recursively adds all
     * children of the root to the grammar, too. The root production cannot
     * be changed anymore once set.
     */
    hilti::Result<hilti::Nothing> setRoot(std::unique_ptr<Production> p);

    /**
     * Freezes the grammar, computes the parsing tables for all previously
     * added productions, and then registers the look-ahead sets with all
     * `LookAhead` productions. If this method fails, grammar and production
     * will be left in an undefined state.
     *
     * @return error if the parsing tables couldn't be computed (e.g., due to
     * ambiguities); the error description will then be describing the issue.
     */
    hilti::Result<hilti::Nothing> finalize();

    /** Returns the root production, if set already. */
    Production* root() const { return _root.get(); }

    /**
     * Returns a closure of all the grammar's productions starting with the
     * root. The result maps each production's symbol to the production
     * itself. Productions without symbols are not included.
     *
     * @note will return an empty map until the root production gets set.
     */
    const auto& productions() const { return _prods; }

    /**
     * Returns the set of look-ahead terminals for a given production.
     *
     * @param p production to examome
     * @param parent if given and *p* is nullable, then include any look-aheads
     * of the parent as well
     *
     * @return set of non-epsilon terminal productions, or an error if a
     * non-terminal led to the set being ambiguous. Note that the set may
     * contain terminals that are not literals.
     */
    hilti::Result<production::Set> lookAheadsForProduction(const Production* p, const Production* parent = {}) const;

    /** Returns the set of look-ahead symbols that the grammar uses. */
    const auto& lookAheadsInUse() const { return _look_aheads_in_use; }

    /**
     * Prints the grammar in a (somewhat) human readable form. This is for
     * debugging. In *verbose* mode, the grammar and all the internal
     * nullable/first/follow tables are printed.
     */
    void printTables(std::ostream& out, bool verbose = false);

private:
    void _addProduction(Production* p);
    void _simplify();
    hilti::Result<hilti::Nothing> _computeTables();
    hilti::Result<hilti::Nothing> _check();
    production::Set _computeClosure(Production* p);
    bool _add(std::map<std::string, std::set<std::string>>* tbl, Production* dst, const std::set<std::string>& src,
              bool changed);
    bool _isNullable(const Production* p) const;
    bool _isNullable(std::vector<Production*>::const_iterator i, std::vector<Production*>::const_iterator j) const;
    std::set<std::string> _getFirst(const Production* p) const;
    std::set<std::string> _getFirstOfRhs(const std::vector<Production*>& rhs) const;
    std::string _productionLocation(const Production* p) const;
    std::vector<std::vector<Production*>> _rhss(const Production* p);
    void _closureRecurse(production::Set* c, Production* p);

    std::string _name;
    hilti::Location _location;
    std::unique_ptr<Production> _root;

    // Computed by _computeTables()
    std::map<std::string, Production*> _prods;
    std::map<std::string, std::string> _resolved_mapping;
    std::vector<std::unique_ptr<Production>> _resolved; // retains ownership for resolved productions
    std::vector<std::string> _nterms;
    std::map<std::string, bool> _nullable;
    std::map<std::string, std::set<std::string>> _first;
    std::map<std::string, std::set<std::string>> _follow;
    std::set<uint64_t> _look_aheads_in_use;
};

} // namespace spicy::detail::codegen
