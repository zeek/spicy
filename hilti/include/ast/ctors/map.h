// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/map.h>
#include <hilti/ast/types/unknown.h>

#include <utility>

namespace hilti {
namespace ctor {

/** AST node for a map constructor. */
class Map : public NodeBase, public hilti::trait::isCtor {
public:
    using Element = std::pair<Expression, Expression>;
    Map(const std::vector<Element>& e, const Meta& m = Meta()) : NodeBase(nodes(_inferTypes(e, m), _flatten(e)), m) {}
    Map(Type key, Type value, const std::vector<Element>& e, Meta m = Meta())
        : NodeBase(nodes(std::move(key), std::move(value), _flatten(e)), std::move(m)) {}

    auto keyType() const { return type::effectiveType(child<Type>(0)); }
    auto elementType() const { return type::effectiveType(child<Type>(1)); }

    auto value() const {
        auto exprs = childs<Expression>(2, -1);
        std::vector<Element> elems;
        for ( auto&& i = exprs.begin(); i != exprs.end(); i += 2 )
            elems.emplace_back(std::make_pair(std::move(*i), std::move(*(i + 1))));
        return elems;
    }

    bool operator==(const Map& other) const {
        return keyType() == other.keyType() && elementType() == other.elementType() && value() == other.value();
    }

    /** Implements `Ctor` interface. */
    auto type() const { return type::Map(keyType(), elementType(), meta()); }
    /** Implements `Ctor` interface. */
    bool isConstant() const { return false; }
    /** Implements `Ctor` interface. */
    auto isLhs() const { return false; }
    /** Implements `Ctor` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Ctor` interface. */
    auto isEqual(const Ctor& other) const { return node::isEqual(this, other); }
    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    std::vector<Type> _inferTypes(const std::vector<Element>& e, const Meta& /* m */) {
        auto keys = util::transform(e, [](const auto& e) { return e.first; });
        auto values = util::transform(e, [](const auto& e) { return e.second; });
        return {builder::typeOfExpressions(keys), builder::typeOfExpressions(values)};
    }

    std::vector<Expression> _flatten(const std::vector<Element>& elems) {
        std::vector<Expression> exprs;
        for ( auto&& e : elems ) {
            exprs.emplace_back(e.first);
            exprs.emplace_back(e.second);
        }

        return exprs;
    }
};

} // namespace ctor
} // namespace hilti
