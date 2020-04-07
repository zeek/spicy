// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/all.h>
#include <hilti/ast/builder/expression.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>
#include <hilti/global.h>

using namespace hilti;
using util::fmt;

namespace {

struct Visitor : public visitor::PreOrder<void, Visitor> {
    Visitor(Unit* unit) : unit(unit) {}
    Unit* unit;
    bool modified = false;

    /** Returns a method call's i-th argument. */
    auto methodArgument(const expression::ResolvedOperatorBase& o, int i) {
        auto ctor = o.op2().as<expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor.as<ctor::Tuple>().value()[i];
    }

#if 0
    void preDispatch(const Node& n, int level) override {
        auto indent = std::string(level * 2, ' ');
        std::cerr << "# " << indent << "> " << n.render() << std::endl;
        n.scope()->render(std::cerr, "    | ");
    };
#endif

    template<typename T>
    void replaceNode(position_t* p, T&& n) {
        p->node = std::forward<T>(n);
        modified = true;
    }

    /** Coerces an expression to a given type, recording an error if not possible. */
    std::optional<Expression> coerceTo(Node* n, const Expression& e, const Type& t, bool contextual, bool assignment) {
        if ( t == type::unknown )
            return {};

        bitmask<CoercionStyle> style =
            (assignment ? CoercionStyle::TryAllForAssignment : CoercionStyle::TryAllForMatching);

        if ( contextual )
            style |= CoercionStyle::ContextualConversion;

        if ( auto c = hilti::coerceExpression(e, t, style) )
            return c.nexpr;

        n->setError(fmt("cannot coerce expression '%s' of type '%s' to type '%s'", e, e.type(), t));
        return {};
    }

    Result<std::optional<std::vector<Expression>>> coerceCallArguments(Node* n, std::vector<Expression> exprs,
                                                                       std::vector<declaration::Parameter> params) {
        // Build a tuple to coerce expression according to an OperandList.
        auto src = expression::Ctor(ctor::Tuple(exprs));
        auto dst = type::OperandList::fromParameters(params);

        auto coerced = coerceExpression(src, type::constant(dst), CoercionStyle::TryAllForFunctionCall);
        if ( ! coerced ) {
            auto src_types = util::join(util::transform(exprs, [&](auto e) { return fmt("%s", e.type()); }), ", ");
            auto dst_types = util::join(util::transform(dst.operands(), [&](auto o) { return fmt("%s", o); }), ", ");
            n->setError(fmt("cannot coerce arguments '%s' of types '%s' to parameters '%s'", Expression(src), src_types,
                            dst_types));
            return result::Error("coercion failed");
        }

        if ( ! coerced.nexpr )
            // No change.
            return {std::nullopt};

        return {coerced.nexpr->as<expression::Ctor>().ctor().as<ctor::Tuple>().value()};
    }

    void operator()(const Attribute& n) {
        // TODO(robin): Coerce attributes with expressions.
    }

    void operator()(const ctor::Default& n, position_t p) {
        if ( auto stype = n.type().tryAs<type::Struct>() ) {
            if ( auto x = n.typeArguments(); x.size() ) {
                if ( auto coerced = coerceCallArguments(&p.node, x, stype->parameters()); coerced && *coerced ) {
                    auto m = ctor::Default::setTypeArguments(n, **coerced);
                    replaceNode(&p, std::move(m));
                }
            }
        }
    }

    void operator()(const declaration::Parameter& n, position_t p) {
        if ( auto def = n.default_(); def && def->type() != n.type() )
            if ( auto x = coerceTo(&p.node, *def, n.type(), false, true) ) {
                auto m = declaration::Parameter::setDefault(n, *x);
                replaceNode(&p, std::move(m));
            }
    }

    void operator()(const declaration::LocalVariable& n, position_t p) {
        std::optional<Expression> init;
        std::optional<std::vector<Expression>> args;

        if ( auto def = n.init(); def && def->type() != n.type() ) {
            if ( auto x = coerceTo(&p.node, *def, n.type(), false, true) )
                init = std::move(*x);
        }

        if ( auto stype = n.type().tryAs<type::Struct>() ) {
            if ( ! n.typeArguments().empty() ) {
                if ( auto coerced = coerceCallArguments(&p.node, n.typeArguments(), stype->parameters());
                     coerced && *coerced )
                    args = std::move(*coerced);
            }
        }

        if ( init || args ) {
            Declaration new_ = n;

            if ( init )
                new_ = declaration::LocalVariable::setInit(new_.as<declaration::LocalVariable>(), std::move(*init));

            if ( args )
                new_ = declaration::LocalVariable::setTypeArguments(new_.as<declaration::LocalVariable>(),
                                                                    std::move(*args));

            replaceNode(&p, std::move(new_));
        }
    }

    void operator()(const declaration::GlobalVariable& n, position_t p) {
        std::optional<Expression> init;
        std::optional<std::vector<Expression>> args;

        if ( auto def = n.init(); def && def->type() != n.type() ) {
            if ( auto x = coerceTo(&p.node, *def, n.type(), false, true) )
                init = std::move(*x);
        }

        if ( auto stype = n.type().tryAs<type::Struct>() ) {
            if ( auto x = n.typeArguments(); x.size() ) {
                if ( auto coerced = coerceCallArguments(&p.node, x, stype->parameters()); coerced && *coerced )
                    args = std::move(*coerced);
            }
        }

        if ( init || args ) {
            Declaration new_ = n;

            if ( init )
                new_ = declaration::GlobalVariable::setInit(new_.as<declaration::GlobalVariable>(), std::move(*init));

            if ( args )
                new_ = declaration::GlobalVariable::setTypeArguments(new_.as<declaration::GlobalVariable>(),
                                                                     std::move(*args));

            replaceNode(&p, std::move(new_));
        }
    }

    void operator()(const operator_::generic::New& n, position_t p) {
        if ( auto etype = n.op0().tryAs<expression::Type_>() ) {
            if ( auto stype = etype->typeValue().tryAs<type::Struct>() ) {
                auto args = n.op1().as<expression::Ctor>().ctor().as<ctor::Tuple>().value();
                if ( auto coerced = coerceCallArguments(&p.node, args, stype->parameters()); coerced && *coerced ) {
                    Expression ntuple = expression::Ctor(ctor::Tuple(**coerced), n.op1().meta());
                    auto nop = expression::resolved_operator::setOp1(n, std::move(ntuple));
                    replaceNode(&p, nop);
                }
            }
        }
    }

    void operator()(const operator_::vector::PushBack& n, position_t p) {
        // Need to coerce the element here as the normal overload resolution
        // couldn't know the element type yet.
        auto etype = type::effectiveType(n.op0().type()).as<type::Vector>().elementType();
        auto elem = methodArgument(n, 0);

        if ( etype != elem.type() ) {
            if ( auto x = coerceTo(&p.node, n.op2(), type::Tuple({etype}), false, true) ) {
                auto nop = expression::resolved_operator::setOp2(n, *x);
                replaceNode(&p, nop);
            }
        }
    }

    void operator()(const statement::Assert& n, position_t p) {
        if ( ! n.expectsException() && n.expression().type() != type::Bool() ) {
            if ( auto x = coerceTo(&p.node, n.expression(), type::Bool(), true, false) ) {
                auto m = statement::Assert::setCondition(n, *x);
                replaceNode(&p, std::move(m));
            }
        }
    }

    void operator()(const statement::If& n, position_t p) {
        if ( n.condition() ) {
            if ( n.condition()->type() != type::Bool() ) {
                if ( auto x = coerceTo(&p.node, *n.condition(), type::Bool(), true, false) ) {
                    auto m = statement::If::setCondition(n, *x);
                    replaceNode(&p, std::move(m));
                }
            }
        }

        else {
            auto init = (*n.init()).as<declaration::LocalVariable>();
            Expression ncond = expression::UnresolvedID(init.id());
            Statement nif = statement::If::setCondition(n, ncond);
            replaceNode(&p, std::move(nif));
        }
    }

    void operator()(const statement::Return& n, position_t p) {
        if ( auto func = p.findParent<Function>() ) {
            if ( auto e = n.expression(); e && e->type() != func->get().type().result().type() ) {
                if ( auto x = coerceTo(&p.node, *e, func->get().type().result().type(), false, true) ) {
                    auto m = statement::Return::setExpression(n, *x);
                    replaceNode(&p, std::move(m));
                }
            }
        }
        else
            p.node.setError("return outside of function");
    }

    void operator()(const statement::While& n, position_t p) {
        if ( n.condition() ) {
            if ( n.condition()->type() != type::Bool() ) {
                if ( auto x = coerceTo(&p.node, *n.condition(), type::Bool(), true, false) ) {
                    auto m = statement::While::setCondition(n, *x);
                    replaceNode(&p, std::move(m));
                }
            }
        }

        else {
            auto init = (*n.init()).as<declaration::LocalVariable>();
            auto ninit = declaration::LocalVariable::setInit(init, {}).as<declaration::LocalVariable>();
            ninit = declaration::LocalVariable::setType(ninit, init.type()).as<declaration::LocalVariable>();
            Expression ncond = expression::Assign(expression::UnresolvedID(init.id()), *init.init());

            if ( ncond.type() != type::Bool() && ncond.type() != type::unknown ) {
                if ( auto x = coerceTo(&p.node, ncond, type::Bool(), true, false) ) {
                    ncond = builder::equal(ncond, builder::bool_(true));
                    auto nwhile = statement::While::setInit(n, ninit).as<statement::While>();
                    nwhile = statement::While::setCondition(nwhile, ncond).as<statement::While>();
                    replaceNode(&p, nwhile);
                }
            }
        }
    }

    void operator()(const type::struct_::Field& f, position_t p) {
        if ( auto attrs = f.attributes() ) {
            if ( auto x = attrs->coerceValueTo("&default", f.type()) ) {
                if ( *x ) {
                    auto nattrs = type::struct_::Field::setAttributes(f, *attrs);
                    replaceNode(&p, std::move(nattrs));
                }

                return;
            }
            else
                p.node.setError(fmt("cannot coerce default expression to type '%s'", f.type()));
        }
    }

    void operator()(const expression::Assign& n, position_t p) {
        if ( n.source().type() != n.target().type() ) {
            // We allow assignments from const to non-const here, assignment
            // is by value.
            if ( auto x = coerceTo(&p.node, n.source(), n.target().type(), false, true) ) {
                auto m = expression::Assign::setSource(n, *x);
                replaceNode(&p, std::move(m));
            }
        }
    }

    void operator()(const expression::LogicalAnd& n, position_t p) {
        expression::LogicalAnd nn = n;
        bool changed = false;

        if ( n.op0().type() != type::Bool() ) {
            if ( auto x = coerceTo(&p.node, n.op0(), type::Bool(), true, false) ) {
                nn = expression::LogicalAnd::setOp0(nn, *x).as<expression::LogicalAnd>();
                changed = true;
            }
        }

        if ( n.op1().type() != type::Bool() ) {
            if ( auto x = coerceTo(&p.node, n.op1(), type::Bool(), true, false) ) {
                nn = expression::LogicalAnd::setOp1(nn, *x).as<expression::LogicalAnd>();
                changed = true;
            }
        }

        if ( changed )
            replaceNode(&p, std::move(nn));
    }

    void operator()(const expression::LogicalNot& n, position_t p) {
        if ( n.expression().type() != type::Bool() ) {
            if ( auto x = coerceTo(&p.node, n.expression(), type::Bool(), true, false) ) {
                auto m = expression::LogicalNot::setExpression(n, *x);
                replaceNode(&p, std::move(m));
            }
        }
    }

    void operator()(const expression::LogicalOr& n, position_t p) {
        expression::LogicalOr nn = n;
        bool changed = false;

        if ( n.op0().type() != type::Bool() ) {
            if ( auto x = coerceTo(&p.node, n.op0(), type::Bool(), true, false) ) {
                nn = expression::LogicalOr::setOp0(nn, *x).as<expression::LogicalOr>();
                changed = true;
            }
        }

        if ( n.op1().type() != type::Bool() ) {
            if ( auto x = coerceTo(&p.node, n.op1(), type::Bool(), true, false) ) {
                nn = expression::LogicalOr::setOp1(nn, *x).as<expression::LogicalOr>();
                changed = true;
            }
        }

        if ( changed )
            replaceNode(&p, std::move(nn));
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
            p.node.setError(fmt("cannot coerce expression '%s' to type '%s'", pc.expression(), pc.type()));
    }
};

} // anonymous namespace

bool hilti::detail::applyCoercions(Node* root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/apply-coercions");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);
    return v.modified;
}
