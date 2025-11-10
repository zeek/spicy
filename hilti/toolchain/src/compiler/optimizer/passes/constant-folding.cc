// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

#include "compiler/detail/optimizer/optimizer.h"

using namespace hilti;
using namespace hilti::detail;

namespace {

// Collect the values of boolean constants declared anywhere in the AST. This
// only considers boolean literals, not expressions that would be need to
// computed/folded.
struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

    std::optional<bool> tryAsBoolLiteral(Expression* x) {
        if ( auto* expression = x->tryAs<expression::Ctor>() ) {
            auto* ctor = expression->ctor();

            if ( auto* x = ctor->tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto* bool_ = ctor->tryAs<ctor::Bool>() )
                return {bool_->value()};
        }

        return {};
    }

    void operator()(statement::If* n) final {
        auto bool_ = tryAsBoolLiteral(n->condition());
        if ( ! bool_ )
            return;

        if ( auto* else_ = n->false_() ) {
            if ( ! bool_.value() )
                replaceNode(n, else_);
            else {
                auto* init = n->init();
                auto* condition = n->condition();
                auto* true_ = n->true_();

                // Unlink first so that we don't recreate the nodes (which
                // would require new resolving).
                if ( init )
                    init->removeFromParent();

                if ( condition )
                    condition->removeFromParent();

                if ( true_ )
                    true_->removeFromParent();

                replaceNode(n, builder()->statementIf(init, condition, true_, nullptr));
            }
        }
        else {
            if ( ! bool_.value() )
                removeNode(n);
            else
                replaceNode(n, n->true_());
        }
    }

    void operator()(expression::Ternary* n) final {
        auto bool_ = tryAsBoolLiteral(n->condition());
        if ( ! bool_ )
            return;

        if ( *bool_ )
            replaceNode(n, n->true_());
        else
            replaceNode(n, n->false_());
    }

    void operator()(statement::While* n) final {
        auto* condition = n->condition();
        if ( ! condition )
            return;

        auto bool_ = tryAsBoolLiteral(condition);
        if ( ! bool_ )
            return;

        // If the `while` condition is true we never run the `else` block.
        if ( *bool_ && n->else_() ) {
            recordChange(n, "removing else block of while loop with true condition");
            n->removeElse(context());
        }

        // If the `while` condition is false we never enter the loop, and
        // run either the `else` block if it is present or nothing.
        else if ( ! *bool_ ) {
            if ( n->else_() )
                replaceNode(n, n->else_(), "replacing while loop with its else block");
            else {
                recordChange(n, "removing while loop with false condition");
                n->parent()->removeChild(n->as<Node>());
            }
        }
    }
};

optimizer::Result run(Optimizer* optimizer) {
    Collector collector(optimizer);
    collector.run();

    auto modified = optimizer::Result::Unchanged;

    while ( true ) {
        if ( Mutator(optimizer, &collector).run() )
            modified = optimizer::Result::Modified;
        else
            return modified;
    }
}

optimizer::RegisterPass constant_folder({.name = "constant_folding",
                                         .phase = optimizer::Phase::Phase1,
                                         .requires_afterwards = optimizer::Requirements::None,
                                         .run = run});

} // namespace
