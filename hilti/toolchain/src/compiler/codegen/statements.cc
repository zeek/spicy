// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/string.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/statements/all.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

static auto traceStatement(CodeGen* cg, cxx::Block* b, Statement* s, bool skip_location = false) {
    if ( s->isA<statement::Block>() )
        return;

    if ( cg->options().track_location && s->meta().location() && ! skip_location )
        b->addStatement(fmt("  ::hilti::rt::location(\"%s\")", s->meta().location()));

    if ( cg->options().debug_trace ) {
        std::string location;

        if ( s->meta().location() )
            location = fmt("%s: ", s->meta().location().dump(true));

        b->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-trace", "%s: %s"))", location,
                            util::escapeUTF8(s->printRaw(), hilti::rt::render_style::UTF8::EscapeQuotes)));
    }
}

namespace {

struct Visitor : hilti::visitor::PreOrder {
    Visitor(CodeGen* cg, cxx::Block* b) : cg(cg), block(b) {}

    CodeGen* cg;
    cxx::Block* block;

    int level = 0;

    void operator()(statement::Assert* n) final {
        auto throw_with_msg = [&](const cxx::Expression& msg) {
            return fmt("throw ::hilti::rt::AssertionFailure(::hilti::rt::to_string_for_print(%s), \"%s\")", msg,
                       n->meta().location());
        };

        auto throw_ = [&](Expression* cond, Expression* msg) {
            if ( msg )
                return throw_with_msg(cg->compile(msg));
            else
                return fmt(R"(throw ::hilti::rt::AssertionFailure("failed expression '%s'", "%s"))",
                           util::escapeUTF8(cond->print(), hilti::rt::render_style::UTF8::EscapeQuotes),
                           n->meta().location());
        };

        if ( ! n->expectException() ) {
            cxx::Block stmt;

            if ( cg->options().debug_flow )
                stmt.addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: assertion error"))", n->meta().location()));

            if ( n->expression()->type()->type()->isA<type::Result>() ) {
                const auto* result = HILTI_INTERNAL_ID("result");
                stmt.addStatement(throw_with_msg(fmt("%s.error().description()", result)));
                block->addIf(fmt("auto %s = %s; ! %s", result, cg->compile(n->expression()), result),
                             cxx::Block(std::move(stmt)));
            }
            else {
                stmt.addStatement(throw_(n->expression(), n->message()));
                block->addIf(fmt("! (%s)", cg->compile(n->expression())), cxx::Block(std::move(stmt)));
            }
        }
        else {
            if ( n->exception() )
                logger().internalError("not support currently for testing for specific exception in assertion", n);

            cxx::Block try_body;
            try_body.addTmp(cxx::declaration::Local("_", "::hilti::rt::exception::DisableAbortOnExceptions"));
            try_body.addStatement(fmt("(void)(%s)", cg->compile(n->expression())));

            if ( cg->options().debug_flow )
                try_body.addStatement(
                    fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: assertion error"))", n->meta().location()));

            try_body.addStatement(throw_(n->expression(), n->message()));

            cxx::Block catch_rethrow;
            catch_rethrow.addStatement("throw"); // dummy to  make it non-empty;

            cxx::Block catch_cont;
            catch_cont.addStatement(""); // dummy to  make it non-empty;

            block->addTry(std::move(try_body), {
                                                   {{{}, "const ::hilti::rt::AssertionFailure&"}, catch_rethrow},
                                                   {{{}, "const ::hilti::rt::Exception&"}, catch_cont},
                                               });
        }
    }

    void operator()(statement::Block* n) final {
        if ( level == 0 ) {
            ++level;

            std::optional<Location> prev_location;

            for ( const auto& s : n->statements() ) {
                traceStatement(cg, block, s, prev_location && s->meta().location() == prev_location);

                dispatch(s);
                prev_location = s->meta().location();
            }

            --level;
        }

        else
            block->addBlock(cg->compile(n));
    }

    void operator()(statement::Break* n) final { block->addStatement("break"); }

    void operator()(statement::Continue* n) final { block->addStatement("continue"); }

    void operator()(statement::Comment* n) final {
        auto sep_before = (n->separator() == statement::comment::Separator::Before ||
                           n->separator() == statement::comment::Separator::BeforeAndAfter);
        auto sep_after = (n->separator() == statement::comment::Separator::After ||
                          n->separator() == statement::comment::Separator::BeforeAndAfter);

        block->addComment(n->comment(), sep_before, sep_after);
    }

    void operator()(statement::Declaration* n) final {
        auto* d = n->declaration()->tryAs<declaration::LocalVariable>();

        if ( ! d )
            logger().internalError("statements can only declare local variables");

        std::vector<cxx::Expression> args;
        std::optional<cxx::Expression> init;

        if ( auto* i = d->init() ) {
            if ( ! d->init()->isA<expression::Void>() )
                init = cg->compile(i);
        }

        else {
            if ( auto* s = d->type()->type()->tryAs<type::Struct>() )
                args = cg->compileCallArguments(d->typeArguments(), s->parameters(),
                                                hilti::detail::CodeGen::CtorKind::Parameters);

            init = cg->typeDefaultValue(d->type());
        }

        auto l = cxx::declaration::Local(cxx::ID(d->id()), cg->compile(d->type(), codegen::TypeUsage::Storage),
                                         std::move(args), std::move(init));

        block->addLocal(l);
    }

    void operator()(statement::Expression* n) final { block->addStatement(cg->compile(n->expression())); }

    void operator()(statement::If* n) final {
        std::string init;
        std::string cond;

        if ( auto* x = n->init() ) {
            auto& l = *x;
            std::optional<cxx::Expression> cxx_init;

            if ( auto* i = l.init() )
                cxx_init = cg->compile(i);
            else
                cxx_init = cg->typeDefaultValue(l.init()->type());

            init = fmt("%s %s", cg->compile(l.init()->type(), codegen::TypeUsage::Storage), x->id());

            if ( cxx_init )
                init += fmt(" = %s", *cxx_init);
        }

        if ( n->condition() )
            cond = cg->compile(n->condition());

        std::string head;

        if ( ! init.empty() && ! cond.empty() )
            head = fmt("%s; %s", init, cond);
        else if ( ! init.empty() )
            head = std::move(init);
        else
            head = std::move(cond);

        if ( ! n->false_() )
            block->addIf(std::move(head), cg->compile(n->true_()));
        else
            block->addIf(std::move(head), cg->compile(n->true_()), cg->compile(n->false_()));
    }

    void operator()(statement::For* n) final {
        auto id = cxx::ID(n->local()->id());
        auto seq = cg->compile(n->sequence());
        auto body = cg->compile(n->body());

        if ( n->sequence()->type()->side() == Side::LHS )
            block->addForRange(true, id, fmt("%s", seq), body);
        else {
            cxx::Block b;
            b.setEnsureBracesforBlock();
            b.addTmp(cxx::declaration::Local(HILTI_INTERNAL_ID("seq"), "auto", {}, seq));
            b.addForRange(true, id, fmt("::hilti::rt::range(%s)", HILTI_INTERNAL_ID("seq")), body);
            block->addBlock(std::move(b));
        }
    }

    void operator()(statement::Return* n) final {
        if ( cg->options().debug_flow )
            block->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: return"))", n->meta().location()));

        if ( auto* e = n->expression() )
            block->addStatement(fmt("return %s", cg->compile(e)));
        else
            block->addStatement("return");
    }

    void operator()(statement::SetLocation* n) final {
        const auto& location = n->expression()->as<expression::Ctor>()->ctor()->as<ctor::String>()->value();
        block->addStatement(fmt("::hilti::rt::location(\"%s\")", location));
    }

    void operator()(statement::Switch* n) final {
        // TODO(robin): We generate if-else chain here. We could optimize the case
        // where all expressions are integers and go with a "real" switch in
        // that case.
        cxx::ID cxx_id;
        std::string cxx_type;
        std::string cxx_init;

        auto* cond = n->condition();
        cxx_type = cg->compile(cond->type(), codegen::TypeUsage::Storage);
        cxx_id = cxx::ID(cond->id());
        cxx_init = cg->compile(cond->init());

        bool first = true;
        for ( const auto& c : n->cases() ) {
            if ( c->isDefault() )
                continue; // will handle below

            std::string cond;

            auto exprs = c->preprocessedExpressions();

            if ( exprs.size() == 1 )
                cond = cg->compile(*exprs.begin());
            else
                cond = util::join(exprs | std::views::transform([&](auto e) { return cg->compile(e); }), " || ");

            auto body = cg->compile(c->body());

            if ( first ) {
                block->addIf(fmt("%s %s = %s", cxx_type, cxx_id, cxx_init), std::move(cond), std::move(body));
                first = false;
            }
            else
                block->addElseIf(std::move(cond), std::move(body));
        }

        cxx::Block default_;

        if ( auto* d = n->default_() )
            default_ = cg->compile(d->body());
        else
            default_.addStatement(
                fmt("throw ::hilti::rt::UnhandledSwitchCase(::hilti::rt::to_string_for_print(%s), \"%s\")",
                    (first ? cxx_init : cxx_id), n->meta().location()));

        if ( first )
            block->addBlock(std::move(default_));
        else
            block->addElse(std::move(default_));
    }

    void operator()(statement::Throw* n) final {
        if ( cg->options().debug_flow ) {
            if ( auto* e = n->expression() )
                block->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: throw %s"))", n->meta().location(), *e));
            else
                block->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: throw"))", n->meta().location()));
        }

        if ( auto* e = n->expression() )
            block->addStatement(fmt("throw %s", cg->compile(e)));
        else
            block->addStatement("throw");
    }

    void operator()(statement::Try* n) final {
        std::vector<std::pair<cxx::declaration::Argument, cxx::Block>> catches;

        for ( const auto& c : n->catches() ) {
            cxx::declaration::Argument arg;

            if ( auto* par = c->parameter() ) {
                auto t = cg->compile(par->type(), codegen::TypeUsage::InParameter);
                arg = {cxx::ID(par->id()), std::move(t)};
            }
            else
                arg = {"", cxx::Type("...")};

            catches.emplace_back(std::move(arg), cg->compile(c->body()));
        }

        block->addTry(cg->compile(n->body()), std::move(catches));
    }

    void operator()(statement::While* n) final {
        declaration::LocalVariable* init = nullptr;
        std::optional<cxx::Expression> cxx_init;

        if ( n->init() )
            init = n->init();

        if ( init ) {
            if ( auto* i = init->init() )
                cxx_init = cg->compile(i);
            else
                cxx_init = cg->typeDefaultValue(init->type());
        }

        if ( n->else_() ) {
            // We generate different code if we have an "else" clause.
            cxx::Block inner_wrapper;

            if ( init && ! n->condition() )
                inner_wrapper.addStatement(fmt("%s = %s", init->id(), *cxx_init));

            auto else_ = cg->compile(n->else_());
            else_.addStatement("break");

            if ( n->condition() || ! init )
                inner_wrapper.addIf(fmt("! (%s)", cg->compile(n->condition())), std::move(else_));
            else
                inner_wrapper.addIf(fmt("! %s", init->id()), std::move(else_));

            inner_wrapper.appendFromBlock(cg->compile(n->body()));

            cxx::Block outer_wrapper;

            if ( init ) {
                if ( n->condition() )
                    outer_wrapper.addLocal({cxx::ID(init->id()),
                                            cg->compile(init->type(), codegen::TypeUsage::Storage),
                                            {},
                                            std::move(cxx_init)});
                else
                    outer_wrapper.addLocal(
                        {cxx::ID(init->id()), cg->compile(init->type(), codegen::TypeUsage::Storage)});
            }

            outer_wrapper.addWhile(cxx::Expression("true"), inner_wrapper);
            block->addBlock(std::move(outer_wrapper));
            return;
        }

        std::string sinit;
        std::string cond;

        if ( init ) {
            std::string cxx_init_lhs;
            std::string cxx_init_rhs;

            cxx_init_lhs = fmt("%s %s", cg->compile(init->type(), codegen::TypeUsage::Storage), init->id());

            if ( cxx_init )
                cxx_init_rhs = fmt(" = %s", *cxx_init);

            sinit = (cxx_init_lhs + cxx_init_rhs);
        }

        if ( n->condition() )
            cond = cg->compile(n->condition());

        auto body = cg->compile(n->body());

        if ( sinit.empty() )
            block->addWhile(std::move(cond), body);

        else if ( cond.empty() )
            block->addWhile(std::move(sinit), body);

        else
            // C++ doesn't support having both init and cond in a while-loop.
            // Use a for-loop instead.
            block->addFor(std::move(sinit), std::move(cond), "", body);
    }

    void operator()(statement::Yield* n) final {
        if ( cg->options().debug_flow )
            block->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: yield"))", n->meta().location()));

        block->addStatement("::hilti::rt::detail::yield()");
    }
};

} // anonymous namespace

cxx::Block CodeGen::compile(Statement* s, cxx::Block* b) {
    if ( b ) {
        pushCxxBlock(b);
        traceStatement(this, b, s);
        Visitor(this, b).dispatch(s);
        popCxxBlock();
        return *b;
    }

    auto block = cxx::Block();
    pushCxxBlock(&block);
    traceStatement(this, &block, s);
    Visitor(this, &block).dispatch(s);
    popCxxBlock();
    return block;
}
