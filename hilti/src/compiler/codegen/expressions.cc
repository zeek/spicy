// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/all.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : hilti::visitor::PreOrder<std::string, Visitor> {
    Visitor(CodeGen* cg, bool lhs) : cg(cg), lhs(lhs) {}
    CodeGen* cg;
    bool lhs;

    result_t operator()(const expression::Assign& n) {
        if ( auto c = n.target().tryAs<expression::Ctor>() ) {
            if ( c->ctor().type().isA<type::Tuple>() ) {
                auto t = c->ctor().as<ctor::Tuple>().value();
                auto l = util::join(util::transform(t, [this](auto& x) { return cg->compile(x, true); }), ", ");
                return fmt("std::tie(%s) = %s", l, cg->compile(n.source()));
            }
        }

        return fmt("%s = %s", cg->compile(n.target(), true), cg->compile(n.source()));
    }

    result_t operator()(const expression::Coerced& n) {
        return cg->coerce(cg->compile(n.expression(), lhs), n.expression().type(), n.type());
    }

    result_t operator()(const expression::Ctor& n) {
        auto e = cg->compile(n.ctor());

        if ( ! lhs )
            return std::move(e);

        return cg->addTmp("ctor", e);
    }

    result_t operator()(const expression::Deferred& n) {
        auto type = cg->compile(n.type(), codegen::TypeUsage::Storage);
        auto value = cg->compile(n.expression());

        if ( n.catchException() )
            return fmt(
                "hilti::rt::DeferredExpression<%s>([=]() -> %s { try { return %s; } catch ( ... ) { return "
                "hilti::rt::result::Error(\"n/a\"); } })",
                type, type, value);
        else
            return fmt("hilti::rt::DeferredExpression<%s>([=]() -> %s { return %s; })", type, type, value);
    }

    result_t operator()(const expression::Grouping& n) { return fmt("(%s)", cg->compile(n.expression())); }

    result_t operator()(const expression::Keyword& n) {
        switch ( n.kind() ) {
            case expression::keyword::Kind::Self: return cg->self();
            case expression::keyword::Kind::DollarDollar: return cg->dollardollar();
            default: util::cannot_be_reached();
        }
    }

    result_t operator()(const expression::ListComprehension& n) {
        auto id = cxx::ID(n.id());
        auto input = cg->compile(n.input());
        auto itype = cg->compile(n.input().type().elementType(), codegen::TypeUsage::Storage);
        auto otype = cg->compile(n.output().type(), codegen::TypeUsage::Storage);
        auto output = cg->compile(n.output());
        auto pred = std::string();

        if ( auto c = n.condition() )
            pred = fmt(", [](auto&& %s) -> bool { return %s; }", id, cg->compile(*c));

        return fmt("hilti::rt::list::make<%s, %s>(%s, [](auto&& %s) -> %s { return %s; }%s)", itype, otype, input, id,
                   otype, output, pred);
    }

    result_t operator()(const expression::Member& n) {
        logger().internalError(fmt("expression::Member should never be evaluated ('%s')", n), n);
    }

    result_t operator()(const expression::Move& n) {
        if ( ! lhs )
            return fmt("std::move(%s)", cg->compile(n.expression()));

        return cg->compile(n.expression(), true);
    }

    result_t operator()(const expression::LogicalAnd& n) {
        return fmt("(%s) && (%s)", cg->compile(n.op0()), cg->compile(n.op1()));
    }

    result_t operator()(const expression::LogicalNot& n) { return fmt("! (%s)", cg->compile(n.expression())); }

    result_t operator()(const expression::LogicalOr& n) {
        return fmt("(%s) || (%s)", cg->compile(n.op0()), cg->compile(n.op1()));
    }

    result_t operator()(const expression::ResolvedID& n, position_t p) {
        if ( auto g = n.declaration().tryAs<declaration::GlobalVariable>() ) {
            if ( auto ns = n.id().namespace_(); ! ns.empty() )
                return fmt("%s->%s", cxx::ID(ns, "__globals()"), cxx::ID(n.id().local()));

            return fmt("__globals()->%s", cxx::ID(n.id()));
        }

        if ( auto e = n.declaration().tryAs<declaration::Expression>() )
            return cg->compile(e->expression(), lhs);

        if ( auto c = n.declaration().tryAs<declaration::Constant>() ) {
            if ( c->value().type().isA<type::Enum>() )
                return cg->compile(c->value()); // This constructs the right ID.

            return cxx::ID(cg->options().cxx_namespace_intern, cxx::ID(n.id()));
        }

        if ( auto f = n.declaration().tryAs<declaration::Function>() ) {
            // If we're refering to, but not calling, an "external" function
            // or static method, bind to the externally visible name.
            if ( f->function().callingConvention() == function::CallingConvention::Extern &&
                 (p.path.empty() || ! p.parent().isA<operator_::function::Call>()) )
                return cxx::ID(cg->options().cxx_namespace_extern, cxx::ID(n.id()));
        }

        if ( auto p = n.declaration().tryAs<declaration::Parameter>(); p && p->isStructParameter() ) {
            // Need to adjust here for potential automatic change to a weak reference.
            if ( type::isReferenceType(p->type()) )
                return cxx::Expression(fmt("%s->__p_%s.derefAsValue()", cg->self(), p->id()));
            else
                return cxx::Expression(fmt("%s->__p_%s", cg->self(), p->id()));
        }

        return cxx::ID(n.id());
    }

    result_t operator()(const expression::ResolvedOperator& n) { return cg->compile(n, lhs); }

    result_t operator()(const expression::Ternary& n) {
        return fmt("(%s ? %s : %s)", cg->compile(n.condition()), cg->compile(n.true_()), cg->compile(n.false_()));
    }

    result_t operator()(const expression::TypeWrapped& n) { return cg->compile(n.expression(), lhs); }

    result_t operator()(const expression::UnresolvedID& n, position_t p) {
        hilti::print(std::cerr, p.node);
        hilti::render(std::cerr, p.node);
        logger().internalError("unresolved expression ID", n);
    }

    result_t operator()(const expression::UnresolvedOperator& n, position_t p) {
        hilti::print(std::cerr, p.node);
        hilti::render(std::cerr, p.node);
        logger().internalError("unresolved operator", n);
    }

    result_t operator()(const expression::Void& n) { return "<void-expression>"; }
};

} // anonymous namespace

cxx::Expression CodeGen::compile(const hilti::Expression& e, bool lhs) {
    if ( auto x = Visitor(this, lhs).dispatch(e) )
        return *x;

    logger().internalError(fmt("expression failed to compile ('%s' / %s)", e, e.typename_()), e);
}
