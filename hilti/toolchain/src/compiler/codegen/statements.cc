// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/statements/all.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

inline auto traceStatement(CodeGen* cg, cxx::Block* b, const Statement& s, bool skip_location = false) {
    if ( s.isA<statement::Block>() )
        return;

    if ( cg->options().track_location && s.meta().location() && ! skip_location )
        b->addStatement(fmt("  __location__(\"%s\")", s.meta().location()));

    if ( cg->options().debug_trace )
        b->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-trace", "%s: %s"))", s.meta().location(),
                            util::escapeUTF8(fmt("%s", s), true)));
}

namespace {

struct Visitor : hilti::visitor::PreOrder<void, Visitor> {
    Visitor(CodeGen* cg, cxx::Block* b) : cg(cg), block(b) {}
    CodeGen* cg;

    int level = 0;
    cxx::Block* block;

    void operator()(const statement::Assert& n) {
        std::string throw_;

        if ( n.message() )
            throw_ = fmt("throw ::hilti::rt::AssertionFailure(hilti::rt::to_string_for_print(%s), \"%s\")",
                         cg->compile(*n.message()), n.meta().location());
        else {
            auto msg = std::string(to_node(n.expression()));
            throw_ = fmt(R"(throw ::hilti::rt::AssertionFailure("failed expression '%s'", "%s"))",
                         util::escapeUTF8(msg, true), n.meta().location());
        }

        if ( ! n.expectsException() ) {
            cxx::Block stmt;

            if ( cg->options().debug_flow )
                stmt.addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: assertion error"))", n.meta().location()));

            stmt.addStatement(throw_);
            block->addIf(fmt("! (%s)", cg->compile(n.expression())), cxx::Block(std::move(stmt)));
        }
        else {
            if ( n.exception() )
                logger().internalError("not support currently for testing for specific exception in assertion", n);

            cxx::Block try_body;
            try_body.addTmp(cxx::declaration::Local{"_", "::hilti::rt::exception::DisableAbortOnExceptions"});
            try_body.addStatement(fmt("%s", cg->compile(n.expression())));

            if ( cg->options().debug_flow )
                try_body.addStatement(
                    fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: assertion error"))", n.meta().location()));

            try_body.addStatement(throw_);

            cxx::Block catch_rethrow;
            catch_rethrow.addStatement("throw"); // dummy to  make it non-empty;

            cxx::Block catch_cont;
            catch_cont.addStatement(""); // dummy to  make it non-empty;

            block->addTry(std::move(try_body), {
                                                   {{{}, "const hilti::rt::AssertionFailure&"}, catch_rethrow},
                                                   {{{}, "const hilti::rt::Exception&"}, catch_cont},
                                               });
        }
    }

    void operator()(const statement::Block& n) {
        if ( level == 0 ) {
            ++level;

            std::optional<Location> prev_location;

            for ( const auto& s : n.statements() ) {
                traceStatement(cg, block, s, prev_location && s.meta().location() == prev_location);

                dispatch(s);
                prev_location = s.meta().location();
            }

            --level;
        }

        else
            block->addBlock(cg->compile(n));
    }

    void operator()(const statement::Break& n, position_t p) { block->addStatement("break"); }

    void operator()(const statement::Continue& n, position_t p) { block->addStatement("continue"); }

    void operator()(const statement::Comment& n) {
        auto sep_before = (n.separator() == statement::comment::Separator::Before ||
                           n.separator() == statement::comment::Separator::BeforeAndAfter);
        auto sep_after = (n.separator() == statement::comment::Separator::After ||
                          n.separator() == statement::comment::Separator::BeforeAndAfter);

        block->addComment(n.comment(), sep_before, sep_after);
    }

    void operator()(const statement::Declaration& n) {
        auto d = n.declaration().tryAs<declaration::LocalVariable>();

        if ( ! d )
            logger().internalError("statements can only declare local variables");

        std::vector<cxx::Expression> args;
        std::optional<cxx::Expression> init;

        if ( auto i = d->init() )
            init = cg->compile(*i);

        else {
            if ( auto s = d->type().tryAs<type::Struct>() )
                args = cg->compileCallArguments(d->typeArguments(), s->parameters());

            init = cg->typeDefaultValue(d->type());
        }

        auto l = cxx::declaration::Local{cxx::ID(d->id()), cg->compile(d->type(), codegen::TypeUsage::Storage),
                                         std::move(args), init};

        block->addLocal(l);
    }

    void operator()(const statement::Expression& n) { block->addStatement(cg->compile(n.expression())); }

    void operator()(const statement::If& n) {
        std::string init;
        std::string cond;

        if ( auto x = n.init() ) {
            auto& l = *x;
            std::optional<cxx::Expression> cxx_init;

            if ( auto i = l.init() )
                cxx_init = cg->compile(*i);
            else
                cxx_init = cg->typeDefaultValue(l.init()->type());

            init = fmt("%s %s", cg->compile(l.init()->type(), codegen::TypeUsage::Storage), x->id());

            if ( cxx_init )
                init += fmt(" = %s", *cxx_init);
        }

        if ( n.condition() )
            cond = cg->compile(*n.condition());

        std::string head;

        if ( ! init.empty() && ! cond.empty() )
            head = fmt("%s; %s", init, cond);
        else if ( ! init.empty() )
            head = init;
        else
            head = cond;

        if ( ! n.false_() )
            block->addIf(head, cg->compile(n.true_()));
        else
            block->addIf(head, cg->compile(n.true_()), cg->compile(*n.false_()));
    }

    void operator()(const statement::For& n) {
        auto id = cxx::ID(n.local().id());
        auto seq = cg->compile(n.sequence());
        auto body = cg->compile(n.body());

        if ( ! n.sequence().isTemporary() )
            block->addForRange(true, id, fmt("%s", seq), body);
        else {
            cxx::Block b;
            b.setEnsureBracesforBlock();
            b.addTmp(cxx::declaration::Local{"__seq", "auto", {}, seq});
            b.addForRange(true, id, fmt("::hilti::rt::range(__seq)"), body);
            block->addBlock(std::move(b));
        }
    }

    void operator()(const statement::Return& n, position_t p) {
        if ( cg->options().debug_flow )
            block->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: return"))", n.meta().location()));

        if ( auto e = n.expression() )
            block->addStatement(fmt("return %s", cg->compile(*e)));
        else
            block->addStatement("return");
    }

    void operator()(const statement::SetLocation& n, position_t p) {
        const auto& location = n.expression()->as<expression::Ctor>().ctor().as<ctor::String>().value();
        block->addStatement(fmt("__location__(\"%s\")", location));
    }

    void operator()(const statement::Switch& n, position_t p) {
        // TODO(robin): We generate if-else chain here. We could optimize the case
        // where all expressions are integers and go with a "real" switch in
        // that case.
        cxx::ID cxx_id;
        std::string cxx_type;
        std::string cxx_init;

        const auto& cond = n.condition();
        cxx_type = cg->compile(cond.type(), codegen::TypeUsage::Storage);
        cxx_id = cxx::ID(cond.id());
        cxx_init = cg->compile(*cond.init());

        bool first = true;
        for ( const auto& c : n.cases() ) {
            if ( c.isDefault() )
                continue; // will handle below

            std::string cond;

            auto exprs = c.preprocessedExpressions();

            if ( exprs.size() == 1 )
                cond = cg->compile(*exprs.begin());
            else
                cond = util::join(node::transform(exprs, [&](auto& e) { return cg->compile(e); }), " || ");

            auto body = cg->compile(c.body());

            if ( first ) {
                block->addIf(fmt("%s %s = %s", cxx_type, cxx_id, cxx_init), cond, body);
                first = false;
            }
            else
                block->addElseIf(cond, body);
        }

        cxx::Block default_;

        if ( auto d = n.default_() )
            default_ = cg->compile(d->body());
        else
            default_.addStatement(
                fmt("throw hilti::rt::UnhandledSwitchCase(hilti::rt::to_string_for_print(%s), \"%s\")",
                    (first ? cxx_init : cxx_id), n.meta().location()));

        if ( first )
            block->addBlock(std::move(default_));
        else
            block->addElse(std::move(default_));
    }

    void operator()(const statement::Throw& n, position_t p) {
        if ( cg->options().debug_flow ) {
            if ( auto e = n.expression() )
                block->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: throw %s"))", n.meta().location(), *e));
            else
                block->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: throw"))", n.meta().location()));
        }

        if ( auto e = n.expression() )
            block->addStatement(fmt("throw %s", cg->compile(*e)));
        else
            block->addStatement("throw");
    }

    void operator()(const statement::Try& n, position_t p) {
        std::vector<std::pair<cxx::declaration::Argument, cxx::Block>> catches;

        for ( const auto& c : n.catches() ) {
            cxx::declaration::Argument arg;

            if ( auto par = c.parameter() ) {
                auto t = cg->compile(par->type(), codegen::TypeUsage::InParameter);
                arg = {cxx::ID(par->id()), std::move(t)};
            }
            else
                arg = {"", cxx::Type("...")};

            catches.emplace_back(std::move(arg), cg->compile(c.body()));
        }

        block->addTry(cg->compile(n.body()), std::move(catches));
    }

    void operator()(const statement::While& n) {
        std::optional<declaration::LocalVariable> init;
        std::optional<cxx::Expression> cxx_init;

        if ( n.init() )
            init = n.init();

        if ( init ) {
            if ( auto i = init->init() )
                cxx_init = cg->compile(*i);
            else
                cxx_init = cg->typeDefaultValue(init->type());
        }

        if ( n.else_() ) {
            // We generate different code if we have an "else" clause.
            cxx::Block inner_wrapper;

            if ( ! n.condition() )
                inner_wrapper.addStatement(fmt("%s = %s", init->id(), *cxx_init));

            auto else_ = cg->compile(*n.else_());
            else_.addStatement("break");

            if ( n.condition() )
                inner_wrapper.addIf(fmt("! (%s)", cg->compile(*n.condition())), else_);
            else
                inner_wrapper.addIf(fmt("! %s", init->id()), else_);

            inner_wrapper.appendFromBlock(cg->compile(n.body()));

            cxx::Block outer_wrapper;

            if ( init ) {
                if ( n.condition() )
                    outer_wrapper.addLocal(
                        {cxx::ID(init->id()), cg->compile(init->type(), codegen::TypeUsage::Storage), {}, cxx_init});
                else
                    outer_wrapper.addLocal(
                        {cxx::ID(init->id()), cg->compile(init->type(), codegen::TypeUsage::Storage)});
            }

            outer_wrapper.addWhile(cxx::Expression("true"), inner_wrapper);
            block->addBlock(outer_wrapper);
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

        if ( n.condition() )
            cond = cg->compile(*n.condition());

        auto body = cg->compile(n.body());

        if ( sinit.empty() )
            block->addWhile(cond, body);

        else if ( cond.empty() )
            block->addWhile(sinit, body);

        else
            // C++ doesn't support having both init and cond in a while-loop.
            // Use a for-loop instead.
            block->addFor(sinit, cond, "", body);
    }

    void operator()(const statement::Yield& n) {
        if ( cg->options().debug_flow )
            block->addStatement(fmt(R"(HILTI_RT_DEBUG("hilti-flow", "%s: yield"))", n.meta().location()));

        block->addStatement("::hilti::rt::detail::yield()");
    }
};

} // anonymous namespace

cxx::Block CodeGen::compile(const hilti::Statement& s, cxx::Block* b) {
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
