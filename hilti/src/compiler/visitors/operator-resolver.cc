// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <unordered_set>

#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/detail/operator-registry.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/operators/function.h>
#include <hilti/ast/operators/generic.h>
#include <hilti/base/util.h>
#include <hilti/compiler/coercion.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/global.h>

using namespace hilti;
using namespace hilti::detail;

namespace hilti::logging::debug {
inline const DebugStream Resolver("resolver");
} // namespace hilti::logging::debug

/** Returns a set of overload alternatives matching given operand expression. */
static std::vector<Node> _resolve(const std::vector<Operator>& candidates, const std::vector<Expression>& operands,
                                  const Meta& meta, bool disallow_type_changes = false) {
    static const std::vector<bitmask<CoercionStyle>> styles = {
        CoercionStyle::PreferOriginalType | CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch,
        CoercionStyle::PreferOriginalType | CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch |
            CoercionStyle::TryConstPromotion,
        CoercionStyle::PreferOriginalType | CoercionStyle::OperandMatching | CoercionStyle::TryExactMatch |
            CoercionStyle::TryConstPromotion | CoercionStyle::TryCoercion,
    };

    auto deref_operands = [&](const std::vector<Expression>& ops) {
        std::vector<Expression> nops;

        for ( auto&& op : ops ) {
            if ( type::isReferenceType(op.type()) )
                nops.push_back(builder::type_wrapped(builder::deref(op), op.type().dereferencedType()));
            else
                nops.push_back(op);
        }

        return nops;
    };

    auto try_candidate = [&](const auto& c, const std::vector<Expression>& ops, auto style,
                             const auto& dbg_msg) -> std::optional<Expression> {
        auto nops = coerceOperands(ops, c.operands(), style);
        if ( ! nops ) {
            if ( (style & CoercionStyle::TryCoercion) && ! (style & CoercionStyle::DisallowTypeChanges) ) {
                // If any of the operands is a reference type, try the
                // derefed operands, too.
                for ( const auto& op : ops ) {
                    if ( type::isReferenceType(op.type()) )
                        nops = coerceOperands(deref_operands(ops), c.operands(), style);
                }
            }
        }

        if ( ! nops )
            return {};

        auto r = c.instantiate(nops->second, meta);
        HILTI_DEBUG(logging::debug::Resolver, util::fmt("-> %s, resolves to %s %s", dbg_msg, to_node(r),
                                                        (r.isConstant() ? "(const)" : "(non-const)")));
        return r;
    };

    for ( auto style : styles ) {
        if ( disallow_type_changes )
            style |= CoercionStyle::DisallowTypeChanges;

        HILTI_DEBUG(logging::debug::Resolver, util::fmt("style: %s", to_string(style)));
        logging::DebugPushIndent _(logging::debug::Resolver);

        std::vector<Node> resolved;

        for ( const auto& c : candidates ) {
            HILTI_DEBUG(logging::debug::Resolver, util::fmt("candidate: %s", c.typename_()));
            logging::DebugPushIndent _(logging::debug::Resolver);

            if ( auto r = try_candidate(c, operands, style, "candidate matches") )
                resolved.emplace_back(std::move(*r));
            else {
                // Try to swap the operators for commutative operators.
                if ( operator_::is_commutative(c.kind()) && operands.size() == 2 ) {
                    if ( auto r = try_candidate(c, {operands[1], operands[0]}, style,
                                                "candidate matches with operands swapped") )
                        resolved.emplace_back(std::move(*r));
                }
            }
        }

        if ( resolved.size() )
            return resolved;
    }

    return {};
}

namespace {

/** Visitor that applies common AST transformation before the actual operator resolution process. */
struct Normalizer : public hilti::visitor::PostOrder<void, Normalizer> {
    Normalizer(hilti::Module* module) : module(module) {}

    hilti::Module* module;
    bool modified = false;

    template<typename T>
    void replaceNode(position_t* p, T&& n) {
        auto x = p->node;
        p->node = std::forward<T>(n);
        p->node.setOriginalNode(module->preserve(x));
        modified = true;
    }

#if 0
    void preDispatch(const Node& n, int level) override {
        auto indent = std::string(level * 2, ' ');
        std::cerr << "#1 " << indent << "> " << n.render() << std::endl;
        n.scope()->render(std::cerr, "    | ");
    };
#endif

    void operator()(const expression::UnresolvedOperator& u, position_t p) {
        // Replace member operators that work on references with
        // corresponding versions that first deref the target instance.

        auto deref_op0 = [&]() {
            std::vector<Expression> ops = u.operands();
            ops[0] = hilti::expression::UnresolvedOperator(hilti::operator_::Kind::Deref, {ops[0]}, ops[0].meta());
            Expression x = hilti::expression::UnresolvedOperator(u.kind(), std::move(ops), u.meta());
            replaceNode(&p, std::move(x));
        };

        switch ( u.kind() ) {
            case operator_::Kind::Member:
            case operator_::Kind::MemberCall:
            case operator_::Kind::HasMember:
            case operator_::Kind::TryMember: {
                if ( type::isReferenceType(u.operands()[0].type()) )
                    deref_op0();
            }
            default: { /* ignore */
            }
        }
    }
};

struct Visitor : public hilti::visitor::PostOrder<void, Visitor> {
    bool modified = false;

#if 0
    void preDispatch(const Node& n, int level) override {
        auto indent = std::string(level * 2, ' ');
        std::cerr << "#2 " << indent << "> " << n.render() << std::endl;
        n.scope()->render(std::cerr, "    | ");
    };
#endif

    bool resolveOperator(const expression::UnresolvedOperator& u, position_t p) { // TODO(google-runtime-references)
        for ( const auto& o : u.operands() ) {
            if ( o.type().isA<type::Unknown>() )
                return false;
        }

        HILTI_DEBUG(logging::debug::Resolver,
                    util::fmt("== resolving operator: %s (%s)", to_node(u), u.meta().location().render(true)));
        logging::DebugPushIndent _(logging::debug::Resolver);

        std::vector<Node> resolved;

        // TODO(robin): This was meant to be "const auto&", but that crashes. Why?
        auto candidates = operator_::registry().allOfKind(u.kind());

        if ( u.kind() == operator_::Kind::MemberCall && u.operands().size() >= 2 ) {
            // Pre-filter list of all member-call operators down to those
            // with matching methods. This is just a performance
            // optimization.
            auto member = u.operands()[1].template as<expression::Member>().id();

            auto filtered = util::filter(candidates, [&](const auto& c) {
                return std::get<Type>(c.operands()[1].type).template as<type::Member>() == member;
            });

            resolved = _resolve(candidates, u.operands(), u.meta());
        }

        else
            resolved = _resolve(candidates, u.operands(), u.meta(), u.kind() == operator_::Kind::Cast);

        if ( resolved.empty() ) {
            p.node.addError(util::fmt("cannot resolve operator: %s", renderOperatorInstance(u)));
            return false;
        }

        if ( resolved.size() > 1 ) {
            std::vector<std::string> context = {"candidates:"};
            for ( auto i : resolved )
                context.emplace_back(util::fmt("- %s [%s]",
                                               renderOperatorPrototype(i.as<expression::ResolvedOperator>()),
                                               i.typename_()));

            p.node.addError(util::fmt("operator usage is ambiguous: %s", renderOperatorInstance(u)),
                            std::move(context));
            return true;
        }

        p.node = resolved[0];
        modified = true;

#ifndef NDEBUG
        Expression new_op = p.node.as<expression::ResolvedOperator>();
        HILTI_DEBUG(logging::debug::Resolver,
                    util::fmt("=> resolved to %s (result: %s, expression is %s)", p.node.render(), new_op,
                              (new_op.isConstant() ? "const" : "non-const")));
#endif
        return true;
    }

    bool resolveFunctionCall(const expression::UnresolvedOperator& u, position_t p) {
        auto operands = u.operands();

        if ( operands.size() != 2 )
            return false;

        auto callee = operands[0].tryAs<expression::UnresolvedID>();
        auto args_ctor = operands[1].tryAs<expression::Ctor>();

        if ( ! callee )
            return false;

        if ( ! args_ctor ) {
            p.node.addError("function call's argument must be a tuple constant");
            return true;
        }

        auto args = args_ctor->ctor().tryAs<ctor::Tuple>();

        if ( ! args ) {
            p.node.addError("function call's argument must be a tuple constant");
            return true;
        }

        std::vector<Operator> candidates;

        for ( auto i = p.path.rbegin(); i != p.path.rend(); i++ ) {
            auto resolved = (**i).scope()->lookupAll(callee->id());

            if ( resolved.empty() )
                continue;

            for ( auto& r : resolved ) {
                auto d = r.node->tryAs<declaration::Function>();

                if ( ! d ) {
                    p.node.addError(util::fmt("ID '%s' resolves to something other than just functions", callee->id()));
                    return true;
                }

                if ( r.external && d->linkage() != declaration::Linkage::Public ) {
                    p.node.addError(util::fmt("function has not been declared public: %s", r.qualified));
                    return true;
                }

                auto op = operator_::function::Call::Operator(r, d->function().type());
                candidates.emplace_back(op);
            }

            std::vector<Node> overloads = _resolve(candidates, operands, u.meta());

            if ( overloads.empty() )
                break;

            if ( overloads.size() > 1 ) {
                // Ok as long as it's all the same hook, report otherwise.
                auto function = [](auto n) {
                    auto rid =
                        n.template as<expression::ResolvedOperator>().op0().template as<expression::ResolvedID>();
                    return std::make_pair(rid.id(), rid.declaration().template as<declaration::Function>().function());
                };

                auto [id, func] = function(overloads[0]);

                if ( func.type().flavor() != type::function::Flavor::Hook ) {
                    std::vector<std::string> context = {"candidate functions:"};

                    for ( auto i : overloads )
                        context.emplace_back(
                            util::fmt("- %s", renderOperatorPrototype(i.as<expression::ResolvedOperator>())));

                    p.node.addError(util::fmt("call is ambiguous: %s", renderOperatorInstance(u)), std::move(context));
                    return true;
                }

                for ( auto& i : overloads ) {
                    auto [oid, ofunc] = function(i);
                    if ( id != oid || Type(func.type()) != Type(ofunc.type()) ) {
                        std::vector<std::string> context = {"candidate functions:"};

                        for ( auto i : overloads )
                            context.emplace_back(
                                util::fmt("- %s", renderOperatorPrototype(i.as<expression::ResolvedOperator>())));


                        p.node.addError(util::fmt("call is ambiguous: %s", renderOperatorInstance(u)),
                                        std::move(context));
                        return true;
                    }
                }
            }

            // Found a match.
            HILTI_DEBUG(logging::debug::Resolver,
                        util::fmt("resolved function call %s to %s", callee->id(), overloads.front().render()),
                        p.node.location());

            p.node = overloads.front();
            modified = true;
            return true;
        }

        std::vector<std::string> context;

        if ( ! candidates.empty() ) {
            context.emplace_back("candidate functions:");
            for ( const auto& i : candidates ) {
                auto rop = i.instantiate(u.operands(), u.meta()).as<expression::ResolvedOperator>();
                context.emplace_back(util::fmt("- %s", renderOperatorPrototype(rop)));
            }
        }

        p.node.addError(util::fmt("call does not match any function: %s", renderOperatorInstance(u)),
                        std::move(context));
        return true;
    }

    bool resolveMethodCall(const expression::UnresolvedOperator& u, position_t p) {
        auto operands = u.operands();

        if ( operands.size() != 3 )
            return false;

        auto stype = type::effectiveType(operands[0].type()).tryAs<type::Struct>();
        auto callee = operands[1].tryAs<expression::Member>();
        auto args_ctor = operands[2].tryAs<expression::Ctor>();

        if ( ! (stype && callee) )
            return false;

        if ( ! args_ctor ) {
            p.node.addError("method call's argument must be a tuple constant");
            return true;
        }

        auto args = args_ctor->ctor().tryAs<ctor::Tuple>();

        if ( ! args ) {
            p.node.addError("method call's argument must be a tuple constant");
            return true;
        }

        auto fields = stype->fields(callee->id());

        if ( fields.empty() ) {
            p.node.addError(util::fmt("struct type does not have a method `%s`", callee->id()));
            return false; // Continue trying to find another match.
        }

        for ( auto& f : fields ) {
            if ( ! f.type().isA<type::Function>() ) {
                p.node.addError(util::fmt("struct attribute '%s' is not a function", callee->id()));
                return true;
            }
        }

        auto candidates = util::transform(fields, [&](const auto& f) -> Operator {
            return operator_::struct_::MemberCall::Operator(*stype, f);
        });

        std::vector<Node> overloads = _resolve(candidates, operands, u.meta());

        if ( overloads.empty() ) {
            std::vector<std::string> context;

            if ( ! candidates.empty() ) {
                context.emplace_back("candidate methods:");
                for ( const auto& i : candidates ) {
                    auto rop = i.instantiate(u.operands(), u.meta()).as<expression::ResolvedOperator>();
                    context.emplace_back(util::fmt("- %s", renderOperatorPrototype(rop)));
                }
            }

            p.node.addError(util::fmt("call does not match any method: %s", renderOperatorInstance(u)),
                            std::move(context));
            return true;
        }

        if ( overloads.size() > 1 ) {
            std::vector<std::string> context = {"candidates:"};
            for ( auto i : overloads )
                context.emplace_back(util::fmt("- %s", renderOperatorPrototype(i.as<expression::ResolvedOperator>())));

            p.node.addError(util::fmt("method call to is ambiguous: %s", renderOperatorInstance(u)),
                            std::move(context));
            return true;
        }

        HILTI_DEBUG(logging::debug::Resolver,
                    util::fmt("resolved method call %s to %s", callee->id(), overloads.front().render()),
                    p.node.location());

        p.node = overloads.front();
        modified = true;
        return true;
    }

    void operator()(const expression::UnresolvedOperator& u, position_t p) {
        if ( u.kind() == operator_::Kind::Call && resolveFunctionCall(u, p) )
            return;

        if ( u.kind() == operator_::Kind::MemberCall && resolveMethodCall(u, p) )
            return;

        if ( resolveOperator(u, p) )
            return;

        if ( u.kind() == operator_::Kind::Cast ) {
            // We hardcode here that a cast<> operator can always perform any
            // legal coercion. This helps in cases where we need to force a
            // specific coercion to take place.
            auto expr = u.operands()[0];
            auto dst = u.operands()[1].as<expression::Type_>().typeValue();

            if ( dst != type::unknown ) {
                const auto style = CoercionStyle::TryAllForMatching | CoercionStyle::ContextualConversion;
                if ( auto c = hilti::coerceExpression(expr, dst, style) ) {
                    HILTI_DEBUG(logging::debug::Resolver, util::fmt("resolved cast to type '%s' through coercion", dst),
                                p.node.location());

                    p.node = operator_::generic::CastedCoercion::Operator().instantiate(u.operands(), u.meta());
                    modified = true;
                    return;
                }
            }
        }
    }
};

} // anonymous namespace

bool detail::resolveOperators(Node* root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/operator-resolver");

    auto n = Normalizer(&root->as<hilti::Module>());
    for ( auto i : n.walk(root) )
        n.dispatch(i);

    auto v = Visitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return n.modified || v.modified;
}
