// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

// Visitor running on the final, optimized AST to perform additional peephole
// optimizations. Will run repeatedly until it performs no further changes.
struct Mutator : public optimizer::visitor::Mutator {
    using optimizer::visitor::Mutator::Mutator;

    // Returns true if statement is `(*self).__error = __error`.
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
            else if ( const auto* x = op0->tryAs<expression::Grouping>() ) {
                op0 = x->expression();
                continue;
            }

            return false;
        }

        assert(deref0);

        const auto* op1 = lhs->op1()->tryAs<expression::Member>();
        if ( ! (op1 && op1->id() == "__error") )
            return false;

        const auto* self = deref0->op0()->tryAs<expression::Name>();
        if ( ! (self && self->id() == "self") )
            return false;

        const auto* rhs = assign->source()->tryAs<expression::Name>();
        if ( ! (rhs && rhs->id() == "__error") )
            return false;

        return true;
    }

    // Returns true if statement is `__error == (*self).__error`.
    bool isErrorPop(const statement::Expression* n) const {
        const auto* assign = n->expression()->tryAs<expression::Assign>();
        if ( ! assign )
            return false;

        const auto* lhs = assign->target()->tryAs<expression::Name>();
        if ( ! (lhs && lhs->id() == "__error") )
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
            else if ( const auto* x = op0->tryAs<expression::Grouping>() ) {
                op0 = x->expression();
                continue;
            }

            return false;
        }

        assert(deref0);

        const auto* op1 = rhs->op1()->tryAs<expression::Member>();
        if ( ! (op1 && op1->id() == "__error") )
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

    void operator()(statement::Expression* n) final {
        // Remove expression statements of the form `default<void>`.
        if ( isDefaultVoid(n) ) {
            recordChange(n, "removing default<void> statement");
            n->parent()->removeChild(n);
        }

        // Remove statement pairs of the form:
        //
        //    (*self).__error = __error;
        //    __error = (*self).__error;
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

optimizer::RegisterPass peephole({.id = PassID::Peephole,
                                  .iterate = false,
                                  .guarantees = Guarantees::FullyResolved | Guarantees::ScopesBuilt |
                                                Guarantees::ConstantsFolded | Guarantees::TypesUnified,
                                  .run = run});

} // namespace
