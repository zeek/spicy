// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/expressions/all.h>
#include <hilti/ast/operators/function.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/reference.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/ast-dumper.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : hilti::visitor::PreOrder {
    Visitor(CodeGen* cg, bool lhs) : cg(cg), lhs(lhs) {}

    CodeGen* cg;
    bool lhs;

    std::optional<cxx::Expression> result;

    void operator()(expression::Assign* n) final {
        result = {fmt("%s = %s", cg->compile(n->target(), true), cg->compile(n->source())), Side::LHS};
    }

    void operator()(expression::BuiltInFunction* n) final {
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
            util::join(n->arguments() | std::views::transform([this](auto x) { return cg->compile(x, lhs); }), ", ");
        cg->popCxxBlock();

        block.addStatement(fmt("%s(%s)", cxx::ID(n->cxxname()), arguments));

        cxx::Formatter f;
        f << block;
        result = fmt("(%s)", f.str());
    }

    void operator()(expression::Coerced* n) final {
        result = cg->coerce(cg->compile(n->expression(), lhs), n->expression()->type(), n->type());
    }

    void operator()(expression::Ctor* n) final { result = cg->compile(n->ctor(), lhs); }

    void operator()(expression::Grouping* n) final {
        auto cxx_expr = cg->compile(n->expression());

        if ( auto* local = n->local() ) {
            cxx::Block block;
            cg->pushCxxBlock(&block);

            auto cxx_type = cg->compile(local->type(), codegen::TypeUsage::Storage);

            std::optional<cxx::Expression> cxx_init;

            if ( auto* init = local->init() )
                cxx_init = cg->compile(init);
            else
                cxx_init = cg->typeDefaultValue(local->type());

            auto cxx_local =
                cxx::declaration::Local(cxx::ID(local->id()), cg->compile(local->type(), codegen::TypeUsage::Storage),
                                        {}, std::move(cxx_init));

            block.addTmp(cxx_local);

            cg->popCxxBlock();

            cxx::Formatter f;
            f.ensure_braces_for_block = false;
            f << block;
            result = fmt("([&](){%s return %s;}())", f.str(), cxx_expr);
        }
        else
            result = fmt("(%s)", cxx_expr);
    }

    void operator()(expression::Keyword* n) final {
        switch ( n->kind() ) {
            case expression::keyword::Kind::Self: result = {cg->self(), Side::LHS}; break;
            case expression::keyword::Kind::DollarDollar: result = {cg->dollardollar(), Side::LHS}; break;
            case expression::keyword::Kind::Captures: result = {HILTI_INTERNAL_ID("captures"), Side::LHS}; break;
            case expression::keyword::Kind::Scope: {
                auto scope = fmt("%s_hlto_scope", cg->options().cxx_namespace_intern);
                auto extern_scope = cxx::declaration::Global(cxx::ID(scope), "uint64_t", {}, {}, "extern");
                cg->unit()->add(extern_scope);
                result = {scope, Side::RHS};
                break;
            }

            default: util::cannotBeReached();
        }
    }

    void operator()(expression::ListComprehension* n) final {
        auto id = cxx::ID(n->local()->id());
        auto input = cg->compile(n->input());
        auto otype = cg->compile(n->output()->type(), codegen::TypeUsage::Storage);
        auto output = cg->compile(n->output());

        auto pred = std::string();
        if ( auto* c = n->condition() )
            pred = fmt(", [](auto&& %s) -> bool { return %s; }", id, cg->compile(c));

        auto [cxx_type, cxx_default] = cg->cxxTypeForVector(n->output()->type());
        result = fmt("::hilti::rt::vector::make(%s({}%s), %s, [](auto&& %s) -> %s { return %s; }%s)", cxx_type,
                     cxx_default, input, id, otype, output, pred);
    }

    void operator()(expression::Member* n) final {
        logger().internalError(fmt("expression::Member should never be evaluated ('%s')", *n), n);
    }

    void operator()(expression::Move* n) final {
        if ( ! lhs )
            result = fmt("std::move(%s)", cg->compile(n->expression()));
        else
            result = cg->compile(n->expression(), true);
    }

    void operator()(expression::LogicalAnd* n) final {
        result = fmt("(%s) && (%s)", cg->compile(n->op0()), cg->compile(n->op1()));
    }

    void operator()(expression::LogicalNot* n) final { result = fmt("! (%s)", cg->compile(n->expression())); }

    void operator()(expression::LogicalOr* n) final {
        result = fmt("(%s) || (%s)", cg->compile(n->op0()), cg->compile(n->op1()));
    }

    void operator()(expression::Name* n) final {
        if ( ! n->resolvedDeclarationIndex() ) {
            logger().internalError(fmt("expression::Name left unresolved (%s)", *n), n);
            return;
        }

        auto* decl = n->resolvedDeclaration();
        assert(decl);
        const auto& fqid = decl->fullyQualifiedID();
        assert(fqid);

        if ( decl->isA<declaration::GlobalVariable>() ) {
            if ( cg->options().cxx_enable_dynamic_globals ) {
                if ( auto ns = fqid.namespace_(); ! ns.empty() )
                    result = {fmt("%s->%s", cxx::ID(ns, HILTI_INTERNAL_ID("globals()")), cxx::ID(fqid.local())),
                              Side::LHS};
                else
                    result = {fmt("%s()->%s", HILTI_INTERNAL_ID("globals"), cxx::ID(fqid)), Side::LHS};
            }
            else
                result = {fmt("(*%s)", cxx::ID(cg->options().cxx_namespace_intern, cxx::ID(fqid))), Side::LHS};

            return;
        }

        if ( auto* e = decl->tryAs<declaration::Expression>() ) {
            result = cg->compile(e->expression(), lhs);
            return;
        }

        if ( auto* c = decl->tryAs<declaration::Constant>() ) {
            if ( c->value()->type()->type()->isA<type::Enum>() )
                result = {cxx::ID(cg->compile(c->value())), Side::LHS};
            else
                result = {cxx::ID(cg->options().cxx_namespace_intern, cxx::ID(fqid)), Side::LHS};

            return;
        }

        if ( auto* f = decl->tryAs<declaration::Function>() ) {
            // If we're referring to, but not calling, an "external" function
            // or static method, bind to the externally visible name.
            if ( (f->function()->ftype()->callingConvention() == type::function::CallingConvention::Extern ||
                  f->function()->ftype()->callingConvention() == type::function::CallingConvention::ExternNoSuspend) &&
                 (! n->parent() || ! n->parent()->isA<operator_::function::Call>()) ) {
                if ( fqid.namespace_().empty() )
                    // Call to local function, don't qualify it.
                    result = {cxx::ID(fqid), Side::LHS};
                else
                    result = {cxx::ID(cg->options().cxx_namespace_extern, fqid), Side::LHS};

                return;
            }
        }

        if ( auto* f = decl->tryAs<declaration::Field>(); f && f->type()->type()->isA<type::Function>() ) {
            // If we're referring to, but not calling, a method,
            // or static method, bind to the externally visible name for the type.
            result = {cxx::ID(cg->options().cxx_namespace_extern, fqid), Side::LHS};
            return;
        }

        if ( auto* param = decl->tryAs<declaration::Parameter>(); param && param->isTypeParameter() ) {
            auto arg = fmt("%s->%s_%s", cg->self(), HILTI_INTERNAL_ID("p"), param->id());
            if ( param->type()->type()->isReferenceType() ) {
                auto derefed = fmt("%s.derefAsValue()", arg);
                if ( auto* strong_ref = param->type()->type()->tryAs<type::StrongReference>() )
                    result = fmt("::hilti::rt::StrongReference<%s>(%s)",
                                 cg->compile(strong_ref->dereferencedType(), codegen::TypeUsage::Ctor), derefed);
                else
                    result = derefed;
            }
            else
                result = {std::move(arg), Side::LHS};

            return;
        }

        result = {cxx::ID(n->id()), Side::LHS};
    }

    void operator()(expression::ConditionTest* n) final {
        auto type = cg->compile(n->type()->type()->as<type::Result>()->dereferencedType(), codegen::TypeUsage::Storage);
        result = fmt("(%s ? ::hilti::rt::make_result(::hilti::rt::Nothing{}) : %s)", cg->compile(n->condition()),
                     cg->compile(n->error()));
    }

    void operator()(expression::ResolvedOperator* n) final { result = cg->compile(n, lhs); }

    void operator()(expression::Ternary* n) final {
        result = fmt("(%s ? %s : %s)", cg->compile(n->condition()), cg->compile(n->true_()), cg->compile(n->false_()));
    }

    void operator()(expression::TypeInfo* n) final {
        auto* t = n->expression()->type();

        if ( auto* tv = t->type()->tryAs<type::Type_>() )
            t = tv->typeValue();

        result = cg->typeInfo(t);
    }

    void operator()(expression::TypeWrapped* n) final { result = cg->compile(n->expression(), lhs); }

    void operator()(expression::UnresolvedOperator* n) final {
        std::cerr << n->print();
        std::cerr << n->dump();
        logger().internalError("unresolved operator", n);
    }

    void operator()(expression::Void* n) final { result = "<void-expression>"; }
};

} // anonymous namespace

cxx::Expression CodeGen::compile(Expression* e, bool lhs) {
    auto v = Visitor(this, lhs);
    if ( auto x = hilti::visitor::dispatch(v, e, [](const auto& v) -> const auto& { return v.result; }) )
        return lhs ? _makeLhs(*x, e->type()) : *x;

    logger().internalError(fmt("expression failed to compile ('%s' / %s)", *e, e->typename_()), e);
}
