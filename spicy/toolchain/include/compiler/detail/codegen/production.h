// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/location.h>
#include <hilti/base/result.h>
#include <hilti/global.h>

namespace spicy {

using hilti::Location;
using hilti::Nothing;
using hilti::Result;
namespace location = hilti::location;

namespace trait {
class isProduction {};
class isTerminal {};
class isNonTerminal {};
class isLiteral : public isTerminal {};
} // namespace trait
} // namespace spicy

#include <hilti/base/type_erase.h>

#include <spicy/ast/types/unit-items/field.h>

namespace spicy::detail::codegen {

class Production;

namespace production {

/* Meta data that the parser builder associates with a production. */
class Meta {
public:
    /** Returns a unit field associated with the production, if set. */
    auto field() const { return _value<type::unit::item::Field>(_field); }

    /**
     * Returns true if there's a field associated with this production, and
     * the production is the top-level entry point for parsing that field
     * (vs. being a nested production further down in the parse tree).
     */
    bool isFieldProduction() const { return _field && _is_field_production; }

    /**
     * If this production corresponds to a container's item field, this
     * returns the container (once set).
     */
    auto container() const { return _value<type::unit::item::Field>(_container); }

    /**
     * If the production corresponds to a for-each hook, this returns the
     * corresponding field (once set).
     */
    auto forEach() const { return _value<type::unit::item::Field>(_for_each); }

    void setField(const NodeRef& n, bool is_field_production) {
        assert(n);
        _is_field_production = is_field_production;
        _field = n;
    }

    void setContainer(const NodeRef& n) {
        assert(n);
        _container = n;
    }

    void setForEach(const NodeRef& n) {
        assert(n);
        _for_each = n;
    }

    NodeRef fieldRef() const { return NodeRef(_field); }
    NodeRef containerRef() const { return NodeRef(_container); }

private:
    template<class T>
    hilti::optional_ref<const T> _value(const NodeRef& n) const {
        if ( n )
            return n->as<T>();

        return {};
    }

    bool _is_field_production = false;
    NodeRef _field;
    NodeRef _container;
    NodeRef _for_each;
};

#include <spicy/autogen/__production.h>

/**
 * Returns a readable representation of a production for diagnostics.
 */
extern std::string to_string(const Production& p);

/**
 * Returns a unique (and stable) token ID for a given string
 * representations of a production.
 */
extern uint64_t tokenID(const std::string& p);

} // namespace production

/**
 * A single production inside a grammar. This is a type-erased class that
 * wraps all types of productions.
 *
 * @note Do not derive from this class. Implement the `Production` interface
 * instead.
 */
class Production final : public production::Production_ {
public:
    /** Constructs a production from an instance of a class implementing the `Production` interface. */
    template<typename T, typename std::enable_if_t<std::is_base_of<trait::isProduction, T>::value>* = nullptr>
    Production(T t) : codegen::production::Production_(std::move(t)) {}

    ~Production() final = default;
    Production() = default;
    Production(const Production&) = default;
    Production(Production&&) noexcept = default;
    Production& operator=(const Production&) = default;
    Production& operator=(Production&&) = default;

    /**
     * Returns a readable representation of the production for diagnostics.
     */
    explicit operator std::string() const { return to_string(*this); }
};

/** Renders a production for diagnostics. */
inline std::ostream& operator<<(std::ostream& out, const Production& p) {
    out << to_string(p);
    return out;
}

/** Returns true if the two production's symbols match. */
inline bool operator==(const Production& p1, const Production& p2) {
    if ( &p1 == &p2 )
        return true;

    return p1.symbol() == p2.symbol();
}

/** Sorts by the productions' symbols. */
inline bool operator<(const Production& p1, const Production& p2) { return p1.symbol() < p2.symbol(); }

namespace production {
/**
 * Returns if inside a list of production list, at least one is nullable.
 * Also returns true if the list of lists is empty to begin with.
 */
extern bool nullable(const std::vector<std::vector<Production>>& rhss);

} // namespace production

/**
 * Common base class for classes implementing the `Production` interface. The
 * base implements a number of the interface methods with standard versions
 * shared across all nodes.
 */
class ProductionBase : public trait::isProduction {
public:
    /**
     * Constructor.
     *
     * @param symbol symbol associated with the production; the symbol must
     *               be unique within the grammar the production is (or will
     *               be) part of (unless it's empty).
     * @param m meta data associated with the
     * @param l location associated with the production
     */
    ProductionBase(std::string symbol, Location l = location::None)
        : _symbol(std::move(symbol)), _location(std::move(l)), _meta(new production::Meta()) {}

    /** Returns true if the production's associated field has a `&size` attribute. */
    bool hasSize() const { return meta().field() && AttributeSet::find(meta().field()->attributes(), "&size"); }

    /** Implements the `Production` interface. */
    const Location& location() const { return _location; }

    /** Implements the `Production` interface. */
    const std::string& symbol() const { return _symbol; }

    /** Implements the `Production` interface. */
    void setSymbol(const std::string& s) { _symbol = s; }

    /** Implements the `Production` interface. */
    std::optional<Expression> filter() const { return _filter; }

    /** Implements the `Production` interface. */
    void setFilter(const Expression& filter) { _filter = filter; }

    /** Implements the `Production` interface. */
    std::optional<Expression> sink() const { return _sink; }

    /** Implements the `Production` interface. */
    void setSink(const Expression& sink) { _sink = sink; }

    /** Implements the `Production` interface. */
    const production::Meta& meta() const { return *_meta; }

    /** Implements the `Production` interface. */
    void setMeta(production::Meta m) { *_meta = std::move(m); }

    /** Implements the `Production` interface. */
    std::shared_ptr<production::Meta> _metaInstance() const { return _meta; }

    void _setMetaInstance(std::shared_ptr<production::Meta> m) { _meta = std::move(m); }

private:
    std::string _symbol;
    Location _location;
    std::optional<Expression> _filter;
    std::optional<Expression> _sink;
    std::shared_ptr<production::Meta> _meta;
};

} // namespace spicy::detail::codegen
