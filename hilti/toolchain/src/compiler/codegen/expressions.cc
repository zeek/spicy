// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/all.h>
#include <hilti/ast/types/reference.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : hilti::visitor::PreOrder<cxx::Expression, Visitor> {
    Visitor(CodeGen* cg, bool lhs) : cg(cg), lhs(lhs) {}
    CodeGen* cg;
    bool lhs;

    result_t operator()(const expression::Assign& n) {
        return {fmt("%s = %s", cg->compile(n.target(), true), cg->compile(n.source())), cxx::Side::LHS};
    }

    result_t operator()(const expression::BuiltinFunction& n) {
        // We use a statement expression (this is an extension supported by
        // both GCC and Clang) in order for this to be callable in global
        // contexts.
        // This "obvious" approach runs into issues there since temporaries
        // potentially created via `CodeGen::compile` require a block which is
        // not present for certain globals:
        //
        //     auto arguments =
        //         util::join(node::transform(n.arguments(), [this](auto& x) { return cg->compile(x, true); }), ", ");
        //
        //     return fmt("%s(%s)", cxx::ID(n.cxxname()), arguments);

        cxx::Block block;
        cg->pushCxxBlock(&block);
        auto arguments =
            util::join(node::transform(n.arguments(), [this](auto& x) { return cg->compile(x, lhs); }), ", ");
        cg->popCxxBlock();

        block.addStatement(fmt("%s(%s)", cxx::ID(n.cxxname()), arguments));

        cxx::Formatter f;
        f << block;
        return fmt("(%s)", f.str());
    }

    result_t operator()(const expression::Coerced& n) {
        return cg->coerce(cg->compile(n.expression(), lhs), n.expression().type(), n.type());
    }

    result_t operator()(const expression::Ctor& n) { return cg->compile(n.ctor(), lhs); }

    result_t operator()(const expression::Deferred& n) {
        auto type = cg->compile(n.type(), codegen::TypeUsage::Storage);
        auto value = cg->compile(n.expression());

        if ( n.catchException() )
            return fmt(
                "::hilti::rt::DeferredExpression<%s>([=]() -> %s { try { return %s; } catch ( ... ) { return "
                "::hilti::rt::result::Error(\"n/a\"); } })",
                type, type, value);
        else
            return fmt("::hilti::rt::DeferredExpression<%s>([=]() -> %s { return %s; })", type, type, value);
    }

    result_t operator()(const expression::Grouping& n) { return fmt("(%s)", cg->compile(n.expression(), lhs)); }

    result_t operator()(const expression::Keyword& n) {
        switch ( n.kind() ) {
            case expression::keyword::Kind::Self: return {cg->self(), cxx::Side::LHS};
            case expression::keyword::Kind::DollarDollar: return {cg->dollardollar(), cxx::Side::LHS};
            case expression::keyword::Kind::Captures: return {"__captures", cxx::Side::LHS};
            case expression::keyword::Kind::Scope: {
                auto scope = fmt("%s_hlto_scope", cg->options().cxx_namespace_intern);
                auto extern_scope =
                    cxx::declaration::Global{.id = cxx::ID(scope), .type = "const char*", .linkage = "extern"};
                cg->unit()->add(extern_scope);
                return {fmt("std::string(%s)", scope), cxx::Side::RHS};
            }

            default: util::cannot_be_reached();
        }
    }

    result_t operator()(const expression::ListComprehension& n) {
        auto id = cxx::ID(n.local().id());
        auto input = cg->compile(n.input());
        auto itype = cg->compile(n.input().type().elementType(), codegen::TypeUsage::Storage);
        auto otype = cg->compile(n.output().type(), codegen::TypeUsage::Storage);
        auto output = cg->compile(n.output());
        auto pred = std::string();
        auto allocator = std::string();

        if ( auto def = cg->typeDefaultValue(n.output().type()) ) {
            allocator = fmt("::hilti::rt::vector::Allocator<%s, %s>", otype, *def);
        }
        else {
            allocator = fmt("std::allocator<%s>", otype);
        }

        if ( auto c = n.condition() )
            pred = fmt(", [](auto&& %s) -> bool { return %s; }", id, cg->compile(*c));

        return fmt("::hilti::rt::vector::make<%s, %s, %s>(%s, [](auto&& %s) -> %s { return %s; }%s)", allocator, itype,
                   otype, input, id, otype, output, pred);
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
            if ( cg->options().cxx_enable_dynamic_globals ) {
                if ( auto ns = n.id().namespace_(); ! ns.empty() )
                    return {fmt("%s->%s", cxx::ID(ns, "__globals()"), cxx::ID(n.id().local())), cxx::Side::LHS};

                return {fmt("__globals()->%s", cxx::ID(n.id())), cxx::Side::LHS};
            }
            else
                return {fmt("(*%s)", cxx::ID(cg->options().cxx_namespace_intern, cxx::ID(n.id()))), cxx::Side::LHS};
        }

        if ( auto e = n.declaration().tryAs<declaration::Expression>() )
            return cg->compile(e->expression(), lhs);

        if ( auto c = n.declaration().tryAs<declaration::Constant>() ) {
            if ( c->value().type().isA<type::Enum>() )
                return {cxx::ID(cg->compile(c->value())), cxx::Side::LHS};

            return {cxx::ID(cg->options().cxx_namespace_intern, cxx::ID(n.id())), cxx::Side::LHS};
        }

        if ( auto f = n.declaration().tryAs<declaration::Function>() ) {
            // If we're referring to, but not calling, an "external" function
            // or static method, bind to the externally visible name.
            if ( (f->function().callingConvention() == function::CallingConvention::Extern ||
                  f->function().callingConvention() == function::CallingConvention::ExternNoSuspend) &&
                 (p.path.empty() || ! p.parent().isA<operator_::function::Call>()) ) {
                if ( n.id().namespace_().empty() )
                    // Call to local function, don't qualify it.
                    return {cxx::ID(n.id()), cxx::Side::LHS};
                else
                    return {cxx::ID(cg->options().cxx_namespace_extern, n.id()), cxx::Side::LHS};
            }
        }

        if ( auto p = n.declaration().tryAs<declaration::Parameter>(); p && p->isTypeParameter() ) {
            if ( type::isReferenceType(p->type()) )
                // Need to adjust here for potential automatic change to a weak reference.
                return fmt("%s->__p_%s.derefAsValue()", cg->self(), p->id());
            else
                return {fmt("%s->__p_%s", cg->self(), p->id()), cxx::Side::LHS};
        }

        return {cxx::ID(n.id()), cxx::Side::LHS};
    }

    result_t operator()(const expression::ResolvedOperator& n) { return cg->compile(n, lhs); }

    result_t operator()(const expression::Ternary& n) {
        return fmt("(%s ? %s : %s)", cg->compile(n.condition()), cg->compile(n.true_()), cg->compile(n.false_()));
    }

    result_t operator()(const expression::TypeInfo& n) {
        Type t = n.expression().type();

        if ( auto tv = t.tryAs<type::Type_>() )
            t = tv->typeValue();

        return cg->typeInfo(t);
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
        return lhs ? _makeLhs(*x, e.type()) : *x;

    logger().internalError(fmt("expression failed to compile ('%s' / %s)", e, e.typename_()), e);
}
