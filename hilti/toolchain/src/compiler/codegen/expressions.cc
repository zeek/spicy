// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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
            util::join(node::transform(n->arguments(), [this](auto x) { return cg->compile(x, lhs); }), ", ");
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

    void operator()(expression::Deferred* n) final {
        auto type = cg->compile(n->type(), codegen::TypeUsage::Storage);
        auto value = cg->compile(n->expression());

        if ( n->catchException() )
            // We can't pass the exception through here, so we just return a
            // default constructed return value.
            result =
                fmt("::hilti::rt::DeferredExpression<%s>([=]() -> %s { try { return %s; } catch ( ... ) { return "
                    "{}; } })",
                    type, type, value);
        else
            result = fmt("::hilti::rt::DeferredExpression<%s>([=]() -> %s { return %s; })", type, type, value);
    }

    void operator()(expression::Grouping* n) final { result = fmt("(%s)", cg->compile(n->expression(), lhs)); }

    void operator()(expression::Keyword* n) final {
        switch ( n->kind() ) {
            case expression::keyword::Kind::Self: result = {cg->self(), Side::LHS}; break;
            case expression::keyword::Kind::DollarDollar: result = {cg->dollardollar(), Side::LHS}; break;
            case expression::keyword::Kind::Captures: result = {"__captures", Side::LHS}; break;
            case expression::keyword::Kind::Scope: {
                auto scope = fmt("%s_hlto_scope", cg->options().cxx_namespace_intern);
                auto extern_scope =
                    cxx::declaration::Global{.id = cxx::ID(scope), .type = "const char*", .linkage = "extern"};
                cg->unit()->add(extern_scope);
                result = {fmt("std::string(%s)", scope), Side::RHS};
                break;
            }

            default: util::cannotBeReached();
        }
    }

    void operator()(expression::ListComprehension* n) final {
        auto id = cxx::ID(n->local()->id());
        auto input = cg->compile(n->input());
        auto itype = cg->compile(n->input()->type()->type()->elementType(), codegen::TypeUsage::Storage);
        auto otype = cg->compile(n->output()->type(), codegen::TypeUsage::Storage);
        auto output = cg->compile(n->output());
        auto pred = std::string();
        auto allocator = std::string();

        if ( auto def = cg->typeDefaultValue(n->output()->type()) ) {
            allocator = fmt("::hilti::rt::vector::Allocator<%s, %s>", otype, *def);
        }
        else {
            allocator = fmt("std::allocator<%s>", otype);
        }

        if ( auto c = n->condition() )
            pred = fmt(", [](auto&& %s) -> bool { return %s; }", id, cg->compile(c));

        result = fmt("::hilti::rt::vector::make<%s, %s, %s>(%s, [](auto&& %s) -> %s { return %s; }%s)", allocator,
                     itype, otype, input, id, otype, output, pred);
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

        auto decl = n->resolvedDeclaration();
        auto fqid = decl->fullyQualifiedID();
        assert(fqid);

        if ( decl->isA<declaration::GlobalVariable>() ) {
            if ( cg->options().cxx_enable_dynamic_globals ) {
                if ( auto ns = fqid.namespace_(); ! ns.empty() )
                    result = {fmt("%s->%s", cxx::ID(ns, "__globals()"), cxx::ID(fqid.local())), Side::LHS};
                else
                    result = {fmt("__globals()->%s", cxx::ID(fqid)), Side::LHS};
            }
            else
                result = {fmt("(*%s)", cxx::ID(cg->options().cxx_namespace_intern, cxx::ID(fqid))), Side::LHS};

            return;
        }

        if ( auto e = decl->tryAs<declaration::Expression>() ) {
            result = cg->compile(e->expression(), lhs);
            return;
        }

        if ( auto c = decl->tryAs<declaration::Constant>() ) {
            if ( c->value()->type()->type()->isA<type::Enum>() )
                result = {cxx::ID(cg->compile(c->value())), Side::LHS};
            else
                result = {cxx::ID(cg->options().cxx_namespace_intern, cxx::ID(fqid)), Side::LHS};

            return;
        }

        if ( auto f = decl->tryAs<declaration::Function>() ) {
            // If we're referring to, but not calling, an "external" function
            // or static method, bind to the externally visible name.
            if ( (f->function()->callingConvention() == function::CallingConvention::Extern ||
                  f->function()->callingConvention() == function::CallingConvention::ExternNoSuspend) &&
                 (! n->parent() || ! n->parent()->isA<operator_::function::Call>()) ) {
                if ( fqid.namespace_().empty() )
                    // Call to local function, don't qualify it.
                    result = {cxx::ID(fqid), Side::LHS};
                else
                    result = {cxx::ID(cg->options().cxx_namespace_extern, fqid), Side::LHS};

                return;
            }
        }

        if ( auto f = decl->tryAs<declaration::Field>(); f && f->type()->type()->isA<type::Function>() ) {
            // If we're referring to, but not calling, a method,
            // or static method, bind to the externally visible name for the type.
            result = {cxx::ID(cg->options().cxx_namespace_extern, fqid), Side::LHS};
            return;
        }

        if ( auto p = decl->tryAs<declaration::Parameter>(); p && p->isTypeParameter() ) {
            if ( p->type()->type()->isReferenceType() )
                // Need to adjust here for potential automatic change to a weak reference.
                result = fmt("%s->__p_%s.derefAsValue()", cg->self(), p->id());
            else
                result = {fmt("%s->__p_%s", cg->self(), p->id()), Side::LHS};

            return;
        }

        result = {cxx::ID(n->id()), Side::LHS};
    }

    void operator()(expression::ResolvedOperator* n) final { result = cg->compile(n, lhs); }

    void operator()(expression::Ternary* n) final {
        result = fmt("(%s ? %s : %s)", cg->compile(n->condition()), cg->compile(n->true_()), cg->compile(n->false_()));
    }

    void operator()(expression::TypeInfo* n) final {
        auto t = n->expression()->type();

        if ( auto tv = t->type()->tryAs<type::Type_>() )
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
    if ( auto x = hilti::visitor::dispatch(v, e, [](const auto& v) { return v.result; }) )
        return lhs ? _makeLhs(*x, e->type()) : *x;

    logger().internalError(fmt("expression failed to compile ('%s' / %s)", *e, e->typename_()), e);
}
