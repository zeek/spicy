// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <string_view>
#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/node.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

// Helper function to detect whether an ID refers to a generated error variable.
bool isErrorId(std::string_view id) {
    // Nominally the ID of the error field is `HILTI_INTERNAL_ID("error")`,
    // but we also allow `__error` for testing.
    return id == HILTI_INTERNAL_ID("error") || id == "__error";
}

// Visitor running on the final, optimized AST to perform additional peephole
// optimizations. Will run repeatedly until it performs no further changes.
struct Mutator : public optimizer::visitor::Mutator {
    using optimizer::visitor::Mutator::Mutator;

    // Returns true if statement is `(*self)._error = _error`.
    bool isErrorPush(const statement::Expression* n) const {
        const auto* assign = n->expression()->tryAs<expression::Assign>();
        if ( ! assign )
            return false;

        const auto* lhs = assign->target()->tryAs<operator_::struct_::MemberNonConst>();
        if ( ! lhs )
            return false;

        const auto* op0 = lhs->op0();
        const operator_::value_reference::Deref* deref0 = nullptr;
        while ( true ) {
            if ( const auto* x = op0->tryAs<operator_::value_reference::Deref>() ) {
                deref0 = x;
                break;
            }
            else if ( const auto* x = op0->tryAs<expression::Grouping>();
                      x && x->expressions().size() == 1 && ! x->local() ) {
                op0 = x->expressions().front();
                continue;
            }

            return false;
        }

        assert(deref0);

        const auto* op1 = lhs->op1()->tryAs<expression::Member>();
        if ( ! (op1 && isErrorId(op1->id())) )
            return false;

        const auto* self = deref0->op0()->tryAs<expression::Name>();
        if ( ! (self && self->id() == "self") )
            return false;

        const auto* rhs = assign->source()->tryAs<expression::Name>();
        if ( ! (rhs && isErrorId(rhs->id())) )
            return false;

        return true;
    }

    // Returns true if statement is `_error == (*self)._error`.
    bool isErrorPop(const statement::Expression* n) const {
        const auto* assign = n->expression()->tryAs<expression::Assign>();
        if ( ! assign )
            return false;

        const auto* lhs = assign->target()->tryAs<expression::Name>();
        if ( ! (lhs && isErrorId(lhs->id())) )
            return false;

        const auto* rhs = assign->source()->tryAs<operator_::struct_::MemberNonConst>();
        if ( ! rhs )
            return false;

        const auto* op0 = rhs->op0();
        const operator_::value_reference::Deref* deref0 = nullptr;
        while ( true ) {
            if ( const auto* x = op0->tryAs<operator_::value_reference::Deref>() ) {
                deref0 = x;
                break;
            }
            else if ( const auto* x = op0->tryAs<expression::Grouping>();
                      x && x->expressions().size() == 1 && ! x->local() ) {
                op0 = x->expressions().front();
                continue;
            }

            return false;
        }

        assert(deref0);

        const auto* op1 = rhs->op1()->tryAs<expression::Member>();
        if ( ! (op1 && isErrorId(op1->id())) )
            return false;

        const auto* self = deref0->op0()->tryAs<expression::Name>();
        if ( ! (self && self->id() == "self") )
            return false;

        return true;
    }

    // Returns true if a given expression statement is `default<void>`.
    bool isDefaultVoid(const statement::Expression* n) const {
        if ( const auto* ctor = n->expression()->tryAs<expression::Ctor>();
             ctor && ctor->ctor()->isA<ctor::Default>() && ctor->type()->type()->isA<type::Void>() ) {
            return true;
        }

        return false;
    }

    // Mutator replacing all uses of an ID referring to a given declaration
    // with a specified expression.
    struct NameReplacer : public optimizer::visitor::Mutator {
        NameReplacer(Optimizer* optimizer, const Declaration* declaration, Expression* expression)
            : optimizer::visitor::Mutator(optimizer), declaration(declaration), expression(expression) {}

        const Declaration* declaration;
        Expression* expression;

        void operator()(expression::Name* n) final {
            if ( n->resolvedDeclaration()->fullyQualifiedID() == declaration->fullyQualifiedID() )
                replaceNode(n, node::deepcopy(context(), expression), "replacing local with expression");
        }
    };

    void operator()(expression::Grouping* n) final {
        if ( const auto* local = n->local() ) {
            // If a grouping has a local variable that is initialized with an
            // expression that does not have any side effects, and none of the
            // groupings expression has any side effects either, then replace any
            // use of the local with the expression itself.
            auto* init = local->init();
            if ( ! init )
                init = builder()->default_(local->type()->type());

            auto may_have_side_effects = state()->cfgCache()->mayHaveSideEffects(init);

            for ( const auto* e : n->expressions() ) {
                if ( state()->cfgCache()->mayHaveSideEffects(e) )
                    may_have_side_effects = true;
            }


            if ( ! may_have_side_effects ) {
                recordChange(n, "removing local variable from grouping");
                NameReplacer(optimizer(), local, init).run(n);
                n->removeLocal(context());
            }
        }
    }

    void operator()(expression::Move* n) final {
        // A top-level move is a no-op and can be replaced by the inside
        // expression.
        if ( n->parent()->isA<statement::Expression>() )
            replaceNode(n, n->expression(), "removing no-op move");
    }

    void operator()(statement::Expression* n) final {
        // Remove expression statements of the form `default<void>`.
        if ( isDefaultVoid(n) ) {
            recordChange(n, "removing default<void> statement");
            n->parent()->removeChild(n);
        }

        // Remove statement pairs of the form:
        //
        //    (*self)._error = _error;
        //    _error = (*self)._error;
        //
        // These will be left behind by the optimizer if a hook call got
        // optimized out in between them.
        else if ( isErrorPush(n) && n->parent() ) {
            auto* parent = n->parent();
            if ( auto* sibling = parent->sibling(n) ) {
                if ( const auto* stmt = sibling->tryAs<statement::Expression>(); stmt && isDefaultVoid(stmt) )
                    // Skip over default<void> statements; they may not have been removed yet.
                    sibling = parent->sibling(sibling);

                if ( sibling )
                    if ( const auto* stmt = sibling->tryAs<statement::Expression>(); stmt && isErrorPop(stmt) ) {
                        recordChange(n, "removing unneeded error push/pop statements");
                        parent->removeChild(n);
                        parent->removeChild(sibling);
                    }
            }
        }
    }

    void operator()(statement::Try* n) final {
        // If a there's only a single catch block that just rethrows, replace
        // the whole try/catch with the block inside.
        if ( auto catches = n->catches(); catches.size() == 1 ) {
            if ( const auto* catch_body = catches.front()->body()->as<statement::Block>();
                 catch_body->statements().size() == 1 ) {
                if ( const auto* throw_ = catch_body->statements().front()->tryAs<statement::Throw>();
                     throw_ && ! throw_->expression() )
                    replaceNode(n, n->body(), "replacing rethrowing try/catch with just the block");
            }
        }
    }
};

bool run(Optimizer* optimizer) { return Mutator(optimizer).run(); }

optimizer::RegisterPass peephole(
    {.id = PassID::Peephole, .iterate = false, .guarantees = Guarantees::ConstantsFolded, .run = run});

} // namespace
