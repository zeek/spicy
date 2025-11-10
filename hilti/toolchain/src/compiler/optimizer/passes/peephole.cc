// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;

namespace {

/**
 * Visitor running on the final, optimized AST to perform additional peephole
 * optimizations. Will run repeatedly until it performs no further changes.
 */
struct Mutator : public optimizer::visitor::Mutator {
    using optimizer::visitor::Mutator::Mutator;

    // Returns true if statement is `(*self).__error = __error`.
    bool isErrorPush(statement::Expression* n) {
        auto* assign = n->expression()->tryAs<expression::Assign>();
        if ( ! assign )
            return false;

        auto* lhs = assign->target()->tryAs<operator_::struct_::MemberNonConst>();
        if ( ! lhs )
            return false;

        auto* op0 = lhs->op0();
        operator_::value_reference::Deref* deref0 = nullptr;
        while ( true ) {
            if ( auto* x = op0->tryAs<operator_::value_reference::Deref>() ) {
                deref0 = x;
                break;
            }
            else if ( auto* x = op0->tryAs<expression::Grouping>() ) {
                op0 = x->expression();
                continue;
            }

            return false;
        }
        assert(deref0);

        auto* op1 = lhs->op1()->tryAs<expression::Member>();
        if ( ! (op1 && op1->id() == "__error") )
            return false;

        auto* self = deref0->op0()->tryAs<expression::Name>();
        if ( ! (self && self->id() == "self") )
            return false;

        auto* rhs = assign->source()->tryAs<expression::Name>();
        if ( ! (rhs && rhs->id() == "__error") )
            return false;

        return true;
    }

    // Returns true if statement is `__error == (*self).__error`.
    bool isErrorPop(statement::Expression* n) {
        auto* assign = n->expression()->tryAs<expression::Assign>();
        if ( ! assign )
            return false;

        auto* lhs = assign->target()->tryAs<expression::Name>();
        if ( ! (lhs && lhs->id() == "__error") )
            return false;

        auto* rhs = assign->source()->tryAs<operator_::struct_::MemberNonConst>();
        if ( ! rhs )
            return false;

        auto* op0 = rhs->op0();
        operator_::value_reference::Deref* deref0 = nullptr;
        while ( true ) {
            if ( auto* x = op0->tryAs<operator_::value_reference::Deref>() ) {
                deref0 = x;
                break;
            }
            else if ( auto* x = op0->tryAs<expression::Grouping>() ) {
                op0 = x->expression();
                continue;
            }

            return false;
        }
        assert(deref0);

        auto* op1 = rhs->op1()->tryAs<expression::Member>();
        if ( ! (op1 && op1->id() == "__error") )
            return false;

        auto* self = deref0->op0()->tryAs<expression::Name>();
        if ( ! (self && self->id() == "self") )
            return false;

        return true;
    }

    void operator()(statement::Expression* n) final {
        // Remove expression statements of the form `default<void>`.
        if ( auto* ctor = n->expression()->tryAs<expression::Ctor>();
             ctor && ctor->ctor()->isA<ctor::Default>() && ctor->type()->type()->isA<type::Void>() ) {
            recordChange(n, "removing default<void> statement");
            n->parent()->removeChild(n);
            return;
        }

        // Remove statement pairs of the form:
        //
        //    (*self).__error = __error;
        //    __error = (*self).__error;
        //
        // These will be left behind by the optimizer if a hook call got
        // optimized out in between them.
        if ( isErrorPush(n) && n->parent() ) {
            auto* parent = n->parent();
            if ( auto* sibling = parent->sibling(n) ) {
                if ( auto* stmt = sibling->tryAs<statement::Expression>() ) {
                    if ( auto* ctor = stmt->expression()->tryAs<expression::Ctor>();
                         ctor && ctor->ctor()->isA<ctor::Default>() && ctor->type()->type()->isA<type::Void>() )
                        // Skip over default<void> statements.
                        sibling = parent->sibling(sibling);
                }
                if ( sibling ) {
                    if ( auto* stmt = sibling->tryAs<statement::Expression>(); stmt && isErrorPop(stmt) ) {
                        recordChange(n, "removing unneeded error push/pop statements");
                        parent->removeChild(n);
                        parent->removeChild(sibling);
                        return;
                    }
                }
            }
        }
    }

    void operator()(statement::Try* n) final {
        // If a there's only a single catch block that just rethrows, replace
        // the whole try/catch with the block inside.
        if ( auto catches = n->catches(); catches.size() == 1 ) {
            const auto& catch_ = catches.front();
            if ( auto* catch_body = catch_->body()->as<statement::Block>(); catch_body->statements().size() == 1 ) {
                if ( auto* throw_ = catch_body->statements().front()->tryAs<statement::Throw>();
                     throw_ && ! throw_->expression() ) {
                    recordChange(n, "replacing rethrowing try/catch with just the block");
                    replaceNode(n, n->body());
                    return;
                }
            }
        }
    }
};

optimizer::Result run(Optimizer* optimizer) { return Mutator(optimizer).run(); }

optimizer::RegisterPass peephole({.name = "peephole",
                                  .order = 20,
                                  .iterate = false,
                                  .requires_afterwards = optimizer::Requirements::CFG,
                                  .run = run});

} // namespace
