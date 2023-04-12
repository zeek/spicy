// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen {

namespace production {
class Resolved;
using Unresolved = Resolved;
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
    Grammar(std::string name, Location l = location::None) : _name(std::move(name)), _location(std::move(l)) {}
    Grammar() = default;
    Grammar(const Grammar&) = default;
    Grammar(Grammar&&) = default;
    ~Grammar() = default;
    Grammar& operator=(Grammar&&) = default;
    Grammar& operator=(const Grammar&) = default;

    /**
     * Returns the name of the grammar. The name uniquely identifies the
     * grammar.
     */
    const std::string& name() const { return _name; }

    /** Returns the location associated with the production. */
    const Location& location() const { return _location; }

    /**
     * Resolves an previous place-holder production with an actual production.
     * Once resolved, parser table construction will use the actual production
     * everywhere where the place-holder is referenced.
     */
    void resolve(production::Unresolved* r, Production p);

    /** Returns a the actual production a resolved production refers to. */
    const Production& resolved(const production::Resolved& r) const;

    /**
     * Sets the root produnction for the grammar. This recursively adds all
     * childrens of the root to the grammar, too. The root production cannot
     * be changeda anymore once set.
     */
    Result<Nothing> setRoot(const Production& p);

    /**
     * Freezes the grammar, computes the parsing tables for all previously
     * added productions, and then registers the look-ahead sets with all
     * `LookAhead` productions. If this method fails, grammar and production
     * will be left in an undefined state.
     *
     * @return error if the parsing tables couldn't be computed (e.g., due to
     * ambiguties); the error description will then be describing the issue.
     */
    Result<Nothing> finalize();

    /** Returns the root production, if set already. */
    std::optional<Production> root() const {
        if ( _root )
            return _prods.at(*_root);

        return {};
    }

    /**
     * Returns a closure of all the grammar's productions starting with the
     * root. The result maps each production's symbol to the production
     * itself. Productions without symbols are not included.
     *
     * @note will return an empty map until the root production gets set.
     */
    const std::map<std::string, Production>& productions() const { return _prods; }

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
    hilti::Result<std::set<Production>> lookAheadsForProduction(Production p,
                                                                std::optional<Production> parent = {}) const;

    /** Returns true if the grammar needs look-ahead for parsing.
     *
     * @note will always return false until the root production gets set.
     */
    bool needsLookAhead() const { return _needs_look_ahead; }

    /**
     * Prints the grammar in a (somewhat) human readable form. This is for
     * debugging. In *verbose* mode, the grammar and all the internal
     * nullable/first/follow tables are printed.
     */
    void printTables(std::ostream& out, bool verbose = false);

private:
    void _addProduction(const Production& p);
    void _simplify();
    Result<Nothing> _computeTables();
    Result<Nothing> _check();
    std::set<Production> _computeClosure(const Production& p);
    bool _add(std::map<std::string, std::set<std::string>>* tbl, const Production& dst,
              const std::set<std::string>& src, bool changed);
    bool _isNullable(const Production& p) const;
    bool _isNullable(std::vector<Production>::const_iterator i, std::vector<Production>::const_iterator j) const;
    std::set<std::string> _getFirst(const Production& p) const;
    std::set<std::string> _getFirstOfRhs(const std::vector<Production>& rhs) const;
    std::string _productionLocation(const Production& p) const;
    std::vector<std::vector<Production>> _rhss(const Production& p) const;

    std::string _name;
    Location _location;
    std::optional<std::string> _root;

    // Computed by _computeTables()
    bool _needs_look_ahead = false;
    std::map<std::string, Production> _prods;
    std::map<std::string, std::string> _resolved;
    std::vector<std::string> _nterms;
    std::map<std::string, bool> _nullable;
    std::map<std::string, std::set<std::string>> _first;
    std::map<std::string, std::set<std::string>> _follow;
};

} // namespace spicy::detail::codegen
