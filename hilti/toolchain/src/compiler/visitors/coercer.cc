// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/ast/all.h>
#include <hilti/ast/builder/expression.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/operators/tuple.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>
#include <hilti/global.h>

using namespace hilti;
using util::fmt;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Coercer("coercer");
} // namespace hilti::logging::debug

namespace {

struct Visitor : public visitor::PreOrder<void, Visitor> {
    Visitor(Unit* unit) : unit(unit) {}
    Unit* unit;
    bool modified = false;

    // Log debug message recording updating attributes.
    void logChange(const Node& old, const Node& new_, const char* desc) {
        HILTI_DEBUG(logging::debug::Coercer,
                    util::fmt("[%s] %s -> %s %s (%s)", old.typename_(), old, desc, new_, old.location()));
    }

    /** Returns a method call's i-th argument. */
    const Expression& methodArgument(const expression::ResolvedOperatorBase& o, size_t i) {
        auto ops = o.op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto coerced = ops.tryAs<expression::Coerced>() )
            ops = coerced->expression();

        if ( auto ctor_ = ops.tryAs<expression::Ctor>() ) {
            auto ctor = ctor_->ctor();

            // If the argument was the result of a coercion unpack its result.
            if ( auto x = ctor.tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto args = ctor.tryAs<ctor::Tuple>(); args && i < args->value().size() )
                return args->value()[i];
        }

        util::cannot_be_reached();
    }

    /**
     * Coerces an expression to a given type, return the new value if it's
     * changed from the the old one. Records an error with the node if coercion
     * is not possible. Will indicate no-change if expression or type hasn't
     * been resolved.
     **/
    std::optional<Expression> coerceTo(Node* n, const Expression& e, const Type& t, bool contextual, bool assignment) {
        if ( ! (expression::isResolved(e) && type::isResolved(t)) )
            return {};

        if ( e.type() == t )
            return {};

        bitmask<CoercionStyle> style =
            (assignment ? CoercionStyle::TryAllForAssignment : CoercionStyle::TryAllForMatching);

        if ( contextual )
            style |= CoercionStyle::ContextualConversion;

        if ( auto c = hilti::coerceExpression(e, t, style) )
            return c.nexpr;

        n->addError(fmt("cannot coerce expression '%s' of type '%s' to type '%s'", e, e.type(), t));
        return {};
    }

    template<typename Container1, typename Container2>
    Result<std::optional<std::vector<Expression>>> coerceCallArguments(Container1 exprs, Container2 params) {
        // Build a tuple to coerce expression according to an OperandList.
        if ( ! expression::isResolved(exprs) )
            return {std::nullopt};

        auto src = expression::Ctor(ctor::Tuple(std::move(exprs.copy())));
        auto dst = type::OperandList::fromParameters(std::move(params));

        auto coerced = coerceExpression(src, type::constant(dst), CoercionStyle::TryAllForFunctionCall);
        if ( ! coerced )
            return result::Error("coercion failed");

        if ( ! coerced.nexpr )
            // No change.
            return {std::nullopt};

        return {coerced.nexpr->template as<expression::Ctor>().ctor().template as<ctor::Tuple>().value().copy()};
    }

    // Will do nothing if expressions or type aren't resolved.
    template<typename Container>
    Result<std::optional<std::vector<Expression>>> coerceExpressions(const Container& exprs, const Type& dst) {
        if ( ! type::isResolved(dst) )
            return {std::nullopt};

        for ( const auto& e : exprs ) {
            if ( ! expression::isResolved(e) )
                return {std::nullopt};
        }

        bool changed = false;
        std::vector<Expression> nexprs;

        for ( const auto& e : exprs ) {
            auto coerced = coerceExpression(e, type::constant(dst), CoercionStyle::TryAllForAssignment);
            if ( ! coerced )
                return result::Error("coercion failed");

            if ( coerced.nexpr )
                changed = true;

            nexprs.emplace_back(std::move(*coerced.coerced));
        }

        if ( changed )
            return {std::move(nexprs)};
        else
            // No change.
            return {std::nullopt};
    }

    /**
     * Coerces a specific call argument to a given type returning the coerced
     * expression (only) if its type has changed.
     */
    Result<std::optional<Expression>> coerceMethodArgument(const expression::ResolvedOperatorBase& o, size_t i,
                                                           const Type& t) {
        auto ops = o.op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto coerced = ops.tryAs<expression::Coerced>() )
            ops = coerced->expression();

        auto ctor_ = ops.as<expression::Ctor>().ctor();

        // If the argument was the result of a coercion unpack its result.
        if ( auto x = ctor_.tryAs<ctor::Coerced>() )
            ctor_ = x->coercedCtor();

        const auto& args = ctor_.as<ctor::Tuple>().value();
        if ( i >= args.size() )
            return {std::nullopt};

        if ( auto narg = hilti::coerceExpression(args[i], t); ! narg )
            return result::Error(fmt("cannot coerce argument %d from %s to %s", i, args[i].type(), t));
        else if ( narg.nexpr ) {
            auto nargs = args.copy();
            nargs[i] = *narg.nexpr;
            return {expression::Ctor(ctor::Tuple(nargs))};
        }

        return {std::nullopt};
    }

    void operator()(const Attribute& n) {
        // TODO(robin): Coerce attributes with expressions.
    }

    void operator()(const ctor::List& n, position_t p) {
        if ( auto coerced = coerceExpressions(n.value(), n.elementType()) ) {
            if ( *coerced ) {
                logChange(p.node, ctor::Tuple(**coerced), "elements");
                p.node.as<ctor::List>().setValue(**coerced);
                modified = true;
            }
        }
        else {
            if ( n.type().elementType() != type::unknown )
                p.node.addError("type mismatch in list elements");
        }
    }

    void operator()(const ctor::Map& n, position_t p) {
        if ( ! (type::isResolved(n.keyType()) && type::isResolved(n.valueType())) )
            return;

        for ( const auto& e : n.value() ) {
            if ( ! (expression::isResolved(e.key()) && expression::isResolved(e.value())) )
                return;
        }

        bool changed = false;

        std::vector<ctor::map::Element> nelems;
        for ( const auto& e : n.value() ) {
            auto k = coerceExpression(e.key(), n.keyType());
            if ( ! k ) {
                p.node.addError("type mismatch in map keys");
                return;
            }

            auto v = coerceExpression(e.value(), n.valueType());
            if ( ! v ) {
                p.node.addError("type mismatch in map values");
                return;
            }

            if ( k.nexpr || v.nexpr ) {
                nelems.emplace_back(*k.coerced, *v.coerced);
                changed = true;
            }
            else
                nelems.push_back(e);
        }

        if ( changed ) {
            logChange(p.node, ctor::Map(nelems), "value");
            p.node.as<ctor::Map>().setValue(nelems);
            modified = true;
        }
    }

    void operator()(const ctor::Set& n, position_t p) {
        auto coerced = coerceExpressions(n.value(), n.elementType());
        if ( ! coerced )
            p.node.addError("type mismatch in set elements");
        else if ( *coerced ) {
            logChange(p.node, ctor::Tuple(**coerced), "value");
            p.node.as<ctor::Set>().setValue(**coerced);
            modified = true;
        }
    }

    void operator()(const ctor::Vector& n, position_t p) {
        auto coerced = coerceExpressions(n.value(), n.elementType());
        if ( ! coerced )
            p.node.addError("type mismatch in vector elements");
        else if ( *coerced ) {
            logChange(p.node, ctor::Tuple(**coerced), "value");
            p.node.as<ctor::Vector>().setValue(**coerced);
            modified = true;
        }
    }

    void operator()(const ctor::Default& n, position_t p) {
        if ( ! type::isResolved(n.type()) )
            return;

        auto t = n.type();

        if ( auto vr = t.tryAs<type::ValueReference>() )
            t = vr->dereferencedType();

        if ( type::takesArguments(t) ) {
            if ( auto x = n.typeArguments(); x.size() ) {
                if ( auto coerced = coerceCallArguments(x, t.parameters()); coerced && *coerced ) {
                    logChange(p.node, ctor::Tuple(**coerced), "call arguments");
                    p.node.as<ctor::Default>().setTypeArguments(std::move(**coerced));
                    modified = true;
                }
            }
        }
    }

    void operator()(const declaration::Constant& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.value(), n.type(), false, true) ) {
            logChange(p.node, *x, "value");
            p.node.as<declaration::Constant>().setValue(*x);
            modified = true;
        }
    }

    void operator()(const declaration::Parameter& n, position_t p) {
        if ( auto def = n.default_() ) {
            if ( auto x = coerceTo(&p.node, *def, n.type(), false, true) ) {
                logChange(p.node, *x, "default value");
                p.node.as<declaration::Parameter>().setDefault(*x);
                modified = true;
            }
        }
    }

    void operator()(const declaration::LocalVariable& n, position_t p) {
        std::optional<Expression> init;
        std::optional<std::vector<Expression>> args;

        if ( auto e = n.init() ) {
            if ( auto x = coerceTo(&p.node, *e, n.type(), false, true) )
                init = std::move(*x);
        }

        if ( type::takesArguments(n.type()) && n.typeArguments().size() ) {
            auto coerced = coerceCallArguments(n.typeArguments(), n.type().parameters());
            if ( coerced && *coerced )
                args = std::move(*coerced);
        }

        if ( init || args ) {
            if ( init ) {
                logChange(p.node, *init, "init expression");
                p.node.as<declaration::LocalVariable>().setInit(*init);
            }

            if ( args ) {
                logChange(p.node, ctor::Tuple(*args), "type arguments");
                p.node.as<declaration::LocalVariable>().setTypeArguments(std::move(*args));
            }

            modified = true;
        }
    }

    void operator()(const declaration::GlobalVariable& n, position_t p) {
        std::optional<Expression> init;
        std::optional<std::vector<Expression>> args;

        if ( auto e = n.init() ) {
            if ( auto x = coerceTo(&p.node, *e, n.type(), false, true) )
                init = std::move(*x);
        }

        if ( type::takesArguments(n.type()) && n.typeArguments().size() ) {
            auto coerced = coerceCallArguments(n.typeArguments(), n.type().parameters());
            if ( coerced && *coerced )
                args = std::move(*coerced);
        }

        if ( init || args ) {
            if ( init ) {
                logChange(p.node, *init, "init expression");
                p.node.as<declaration::GlobalVariable>().setInit(*init);
            }

            if ( args ) {
                logChange(p.node, ctor::Tuple(*args), "type arguments");
                p.node.as<declaration::GlobalVariable>().setTypeArguments(std::move(*args));
            }

            modified = true;
        }
    }

    void operator()(const expression::Ternary& n, position_t p) {
        if ( ! (type::isResolved(n.true_().type()) && type::isResolved(n.false_().type())) )
            return;

        // Coerce the second branch to the type of the first. This isn't quite
        // ideal, but as good as we can do right now.
        if ( auto coerced = coerceExpression(n.false_(), n.true_().type()); coerced && coerced.nexpr ) {
            logChange(p.node, *coerced.nexpr, "ternary");
            p.node.as<expression::Ternary>().setFalse(*coerced.nexpr);
            modified = true;
        }
    }

    void operator()(const operator_::generic::New& n, position_t p) {
        auto etype = n.op0().tryAs<expression::Type_>();
        if ( ! etype )
            return;

        if ( type::takesArguments(etype->typeValue()) ) {
            auto args = n.op1().as<expression::Ctor>().ctor().as<ctor::Tuple>().value();
            if ( auto coerced = coerceCallArguments(args, etype->typeValue().parameters()); coerced && *coerced ) {
                Expression ntuple = expression::Ctor(ctor::Tuple(**coerced), n.op1().meta());
                logChange(p.node, ntuple, "type arguments");
                p.node.as<operator_::generic::New>().setOp1(ntuple);
                modified = true;
            }
        }
    }

    void operator()(const operator_::map::Get& n, position_t p) {
        if ( auto nargs = coerceMethodArgument(n, 1, n.result()) ) {
            if ( *nargs ) {
                logChange(p.node, **nargs, "default value");
                p.node.as<operator_::map::Get>().setOp2(**nargs);
                modified = true;
            }
        }
        else
            p.node.addError(nargs.error());
    }

    // TODO(bbannier): Ideally instead of inserting this coercion we would
    // define the operator to take some `keyType` derived from the type of the
    // passed `map` and perform the coercion automatically when resolving the
    // function call.
    void operator()(const operator_::map::In& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.op0(), n.op1().type().as<type::Map>().keyType(), true, false) ) {
            logChange(p.node, *x, "call argument");
            p.node.as<operator_::map::In>().setOp0(*x);
            modified = true;
        }
    }

    // TODO(bbannier): Ideally instead of inserting this coercion we would
    // define the operator to take some `elementType` derived from the type of the
    // passed `set` and perform the coercion automatically when resolving the
    // function call.
    void operator()(const operator_::set::In& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.op0(), n.op1().type().as<type::Set>().elementType(), true, false) ) {
            logChange(p.node, *x, "call argument");
            p.node.as<operator_::set::In>().setOp0(*x);
            modified = true;
        }
    }

    void operator()(const operator_::vector::PushBack& n, position_t p) {
        if ( ! (expression::isResolved(n.op0()) && expression::isResolved(n.op2())) )
            return;

        // Need to coerce the element here as the normal overload resolution
        // couldn't know the element type yet.
        auto etype = n.op0().type().as<type::Vector>().elementType();
        auto elem = methodArgument(n, 0);

        if ( auto x = coerceTo(&p.node, n.op2(), type::Tuple({etype}), false, true) ) {
            logChange(p.node, *x, "element type");
            p.node.as<operator_::vector::PushBack>().setOp2(*x);
            modified = true;
        }
    }

    void operator()(const statement::Assert& n, position_t p) {
        if ( n.expectsException() )
            return;

        if ( auto x = coerceTo(&p.node, n.expression(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "expression");
            p.node.as<statement::Assert>().setCondition(*x);
            modified = true;
        }
    }

    void operator()(const statement::If& n, position_t p) {
        if ( auto cond = n.condition() ) {
            if ( auto x = coerceTo(&p.node, *cond, type::Bool(), true, false) ) {
                logChange(p.node, *x, "condition");
                p.node.as<statement::If>().setCondition(*x);
                modified = true;
            }
        }
    }

    void operator()(const statement::Return& n, position_t p) {
        auto func = p.findParent<Function>();
        if ( ! func ) {
            p.node.addError("return outside of function");
            return;
        }

        auto e = n.expression();
        if ( ! e )
            return;

        const auto& t = func->get().ftype().result().type();

        if ( auto x = coerceTo(&p.node, *e, t, false, true) ) {
            logChange(p.node, *x, "expression");
            p.node.as<statement::Return>().setExpression(*x);
            modified = true;
        }
    }

    void operator()(const statement::While& n, position_t p) {
        if ( auto cond = n.condition() ) {
            if ( auto x = coerceTo(&p.node, *cond, type::Bool(), true, false) ) {
                logChange(p.node, *x, "condition");
                p.node.as<statement::While>().setCondition(*x);
                modified = true;
            }
        }
    }

    void operator()(const declaration::Field& f, position_t p) {
        if ( auto a = f.attributes() ) {
            AttributeSet attrs = *a;
            if ( auto x = attrs.coerceValueTo("&default", f.type()) ) {
                if ( *x ) {
                    logChange(p.node, attrs, "attributes");
                    p.node.as<declaration::Field>().setAttributes(attrs);
                    modified = true;
                }

                return;
            }
            else
                p.node.addError(fmt("cannot coerce default expression to type '%s'", f.type()));
        }
    }

    void operator()(const expression::Assign& n, position_t p) {
        // We allow assignments from const to non-const here, assignment
        // is by value.
        if ( auto x = coerceTo(&p.node, n.source(), n.target().type(), false, true) ) {
            logChange(p.node, *x, "source");
            p.node.as<expression::Assign>().setSource(*x);
            modified = true;
        }
    }

    void operator()(const expression::BuiltinFunction& n, position_t p) {
        if ( auto coerced = coerceCallArguments(n.arguments(), n.parameters()); coerced && *coerced ) {
            logChange(p.node, ctor::Tuple(**coerced), "call arguments");
            p.node.as<expression::BuiltinFunction>().setArguments(std::move(**coerced));
            modified = true;
        }
    }

    void operator()(const expression::LogicalAnd& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.op0(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "op0");
            p.node.as<expression::LogicalAnd>().setOp0(*x);
            modified = true;
        }

        if ( auto x = coerceTo(&p.node, n.op1(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "op1");
            p.node.as<expression::LogicalAnd>().setOp1(*x);
            modified = true;
        }
    }

    void operator()(const expression::LogicalNot& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.expression(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "expression");
            p.node.as<expression::LogicalNot>().setExpression(*x);
            modified = true;
        }
    }

    void operator()(const expression::LogicalOr& n, position_t p) {
        if ( auto x = coerceTo(&p.node, n.op0(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "op0");
            p.node.as<expression::LogicalOr>().setOp0(*x);
            modified = true;
        }

        if ( auto x = coerceTo(&p.node, n.op1(), type::Bool(), true, false) ) {
            logChange(p.node, *x, "op1");
            p.node.as<expression::LogicalOr>().setOp1(*x);
            modified = true;
        }
    }

    void operator()(const expression::PendingCoerced& pc, position_t p) {
        if ( auto ner = hilti::coerceExpression(pc.expression(), pc.type()); ner.coerced ) {
            if ( ner.nexpr ) {
                // A coercion expression was created, use it.
                p.node = *ner.nexpr;
                modified = true;
            }
            else {
                // Coercion not needed, use original expression.
                p.node = pc.expression();
                modified = true;
            }
        }
        else
            p.node.addError(fmt("cannot coerce expression '%s' to type '%s'", pc.expression(), pc.type()));
    }

    void operator()(const operator_::tuple::CustomAssign& n, position_t p) {
        if ( ! (expression::isResolved(n.op0()) && expression::isResolved(n.op1())) )
            return;

        auto lhs = n.op0().as<expression::Ctor>().ctor().as<ctor::Tuple>();
        auto lhs_type = lhs.type().as<type::Tuple>();
        auto rhs_type = n.op1().type().tryAs<type::Tuple>();

        if ( ! rhs_type || lhs_type.elements().size() != rhs_type->elements().size() )
            // Validator will catch these.
            return;

        if ( lhs_type == *rhs_type )
            // Nothing to coerce.
            return;

        bool changed = false;
        std::vector<Expression> new_elems;

        const auto& lhs_type_elements = lhs_type.elements();
        const auto& rhs_type_elements = rhs_type->elements();

        for ( auto i = 0U; i < lhs_type.elements().size(); i++ ) {
            const auto& lhs_elem_type = lhs_type_elements[i].type();
            auto rhs_elem_type = rhs_type_elements[i].type();
            auto rhs_elem =
                expression::TypeWrapped(operator_::tuple::Index::Operator().instantiate({n.op1(), builder::integer(i)},
                                                                                        n.meta()),
                                        rhs_elem_type);

            if ( auto x = coerceTo(&p.node, rhs_elem, lhs_elem_type, false, true) ) {
                changed = true;
                new_elems.push_back(std::move(*x));
            }
            else
                new_elems.emplace_back(std::move(rhs_elem));
        }

        if ( changed ) {
            auto new_rhs = builder::tuple(new_elems);
            logChange(p.node, new_rhs, "tuple assign");
            p.node.as<operator_::tuple::CustomAssign>().setOp1(new_rhs);
            modified = true;
        }
    }
};

} // anonymous namespace

bool hilti::detail::ast::coerce(Node* root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/ast/coerce");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified;
}
