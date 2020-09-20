// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/types/computed.h>

namespace hilti {
namespace expression {

/**
 * AST node for an expression wrapped into another which does not have a
 * known type yet, for example because IDs are stil unresolved. With a
 * "normal" expression, calling `type()` would yield an unusable type. This
 * expression instead returns a place-holder type that's derived on one of
 * two ways:
 *
 *     1. If the fully resolved type of the expression is actually known
 *        a-priori, it can be jsut passed into the constructor and will then
 *        always be returned, independent of the inner expression's type
 *        itself.
 *
 *     2. If no explicit type is given, `type()` returns a proxy type that
 *        evaluates the expression's type on demand once requested (but not,
 *        crucially, immediately). So once the expression is fully resolved,
 *        this will yield its correct type. In the meantime, the proxy can be
 *        passed around like any other type.
 *
 * In case 1, one can in addition require that the expression's eventual
 * fully-resolved type matches the type that was specified. If it doesn't the
 * validator will then reject the code.
 *
 */
class TypeWrapped : public NodeBase, public trait::isExpression {
public:
    struct ValidateTypeMatch {};

    TypeWrapped(Expression e, Meta m = Meta()) : NodeBase(nodes(std::move(e), node::none), std::move(m)) {}

    TypeWrapped(Expression e, bool change_constness_to, Meta m = Meta())
        : NodeBase(nodes(std::move(e), node::none), std::move(m)), _change_constness_to(change_constness_to) {}

    TypeWrapped(Expression e, Type t, Meta m = Meta()) : NodeBase(nodes(std::move(e), std::move(t)), std::move(m)) {}

    TypeWrapped(Expression e, Type t, ValidateTypeMatch _, Meta m = Meta())
        : NodeBase(nodes(std::move(e), std::move(t)), std::move(m)), _validate_type_match(true) {}

    TypeWrapped(Expression e, NodeRef t, Meta m = Meta())
        : NodeBase(nodes(std::move(e)), std::move(m)), _type_node_ref(std::move(t)) {}

    TypeWrapped(Expression e, NodeRef t, ValidateTypeMatch _, Meta m = Meta())
        : NodeBase(nodes(std::move(e)), std::move(m)), _validate_type_match(true), _type_node_ref(std::move(t)) {}

    auto expression() const { return child<Expression>(0); }
    bool validateTypeMatch() const { return _validate_type_match; }

    bool operator==(const TypeWrapped& other) const {
        return expression() == other.expression() && type() == other.type();
    }

    /** Implements `Expression` interface. */
    bool isLhs() const { return expression().isLhs(); }
    /** Implements `Expression` interface. */
    bool isTemporary() const { return expression().isTemporary(); }
    /** Implements `Expression` interface. */
    Type type() const {
        if ( _type_node_ref )
            return _type_node_ref->template as<Type>();

        if ( auto t = childs()[1].tryAs<Type>() ) {
            if ( t->template isA<type::Computed>() )
                // Don't call effectiveType() here, we want to keep
                // evaluation pending.
                return *t;

            return type::effectiveType(*t);
        }

        if ( _change_constness_to.has_value() )
            return type::Computed(expression(), *_change_constness_to, meta());

        return type::Computed(expression(), meta());
    }

    /** Implements `Expression` interface. */
    auto isConstant() const { return expression().isConstant(); }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }

    /** Implements `Node` interface. */
    auto properties() const { return node::Properties{{"validate_type_match", _validate_type_match}}; }

private:
    std::optional<bool> _change_constness_to;
    bool _validate_type_match = false;
    NodeRef _type_node_ref;
};

} // namespace expression
} // namespace hilti
