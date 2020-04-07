// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expression.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/base/util.h>

namespace hilti {
namespace expression {

namespace keyword {
// Type of a reserved keyword
enum class Kind {
    Self,        /**< `self` */
    DollarDollar /**< `$$` */
};

namespace detail {
constexpr util::enum_::Value<Kind> kinds[] = {{Kind::Self, "self"}, {Kind::DollarDollar, "$$"}};
} // namespace detail

namespace kind {
constexpr auto from_string(const std::string_view& s) { return util::enum_::from_string<Kind>(s, detail::kinds); }
} // namespace kind

constexpr auto to_string(Kind m) { return util::enum_::to_string(m, detail::kinds); }

} // namespace keyword

/** AST node for an expression representing a reservered keyword. */
class Keyword : public NodeBase, public hilti::trait::isExpression {
public:
    Keyword(keyword::Kind kind, Meta m = Meta()) : NodeBase({type::unknown}, std::move(m)), _kind(kind) {}
    Keyword(keyword::Kind kind, Type t, Meta m = Meta()) : NodeBase({std::move(t)}, std::move(m)), _kind(kind) {}
    Keyword(keyword::Kind kind, NodeRef d, Meta m = Meta())
        : NodeBase({node::none}, std::move(m)), _kind(kind), _decl(d) {}

    keyword::Kind kind() const { return _kind; }

    bool operator==(const Keyword& other) const { return _kind == other._kind && type() == other.type(); }

    /** Implements `Expression` interface. */
    bool isLhs() const { return true; }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return false; }
    /** Implements `Expression` interface. */
    Type type() const {
        auto t = type::effectiveType(_decl ? (**_decl).as<declaration::Type>().type() : childs()[0].as<Type>());

        if ( _kind == keyword::Kind::Self )
            t = type::removeFlags(t, type::Flag::Constant);

        return t;
    }

    /** Implements `Expression` interface. */
    auto isConstant() const { return false; }

    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"kind", to_string(_kind)}}; }

    /**
     * Returns a new keyword expression with the resulting type replaced.
     *
     * @param d original expression
     * @param t new type
     * @return new expression that's equal to original one but with the resulting type replaced
     */
    static Expression setType(const Keyword& e, const Type& t) {
        auto x = Expression(e)._clone().as<Keyword>();
        x.childs()[0] = t;
        x._decl = {};
        return x;
    }

private:
    keyword::Kind _kind;
    std::optional<NodeRef> _decl;
};

} // namespace expression
} // namespace hilti
