// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;

namespace {

// Collect the values of boolean constants declared anywhere in the AST. This
// only considers boolean literals, not expressions that would be need to
// computed/folded.
struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    std::map<ID, bool> constants; // indexed by fully qualified ID

    void done() final {
        if ( logger().isEnabled(logging::debug::OptimizerDetail) ) {
            HILTI_DEBUG(logging::debug::OptimizerDetail, "constants:");
            std::vector<std::string> xs;
            for ( const auto& [id, value] : constants )
                HILTI_DEBUG(logging::debug::OptimizerDetail, util::fmt("    %s: value=%d", id, value));
        }
    }

    void operator()(declaration::Constant* n) final {
        if ( ! n->type()->type()->isA<type::Bool>() )
            return;

        const auto& id = n->fullyQualifiedID();
        assert(id);

        if ( auto* ctor = n->value()->tryAs<expression::Ctor>() )
            if ( auto* bool_ = ctor->ctor()->tryAs<ctor::Bool>() )
                constants[id] = bool_->value();
    }
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

    void operator()(expression::Name* n) final {
        auto* decl = n->resolvedDeclaration();
        assert(decl);

        const auto& id = decl->fullyQualifiedID();
        assert(id);

        if ( const auto& constant = collector->constants.find(id); constant != collector->constants.end() ) {
            if ( n->type()->type()->isA<type::Bool>() )
                replaceNode(n, builder()->bool_((constant->second)), "inlining constant");
        }
    }

    void operator()(statement::If* n) final {
        auto bool_ = tryAsBoolLiteral(n->condition());
        if ( ! bool_ )
            return;

        if ( auto* else_ = n->false_() ) {
            if ( ! bool_.value() )
                replaceNode(n, else_);
            else
                replaceNode(n, builder()->statementIf(n->init(), n->condition(), n->true_(), nullptr));
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

    void operator()(expression::LogicalOr* n) final {
        auto lhs = tryAsBoolLiteral(n->op0());
        auto rhs = tryAsBoolLiteral(n->op1());

        if ( lhs && rhs )
            replaceNode(n, builder()->bool_(lhs.value() || rhs.value()));
    }

    void operator()(expression::LogicalAnd* n) final {
        auto lhs = tryAsBoolLiteral(n->op0());
        auto rhs = tryAsBoolLiteral(n->op1());

        if ( lhs && rhs )
            replaceNode(n, builder()->bool_(lhs.value() && rhs.value()));
    }

    void operator()(expression::LogicalNot* n) final {
        auto bool_ = tryAsBoolLiteral(n->expression());
        if ( ! bool_ )
            return;

        replaceNode(n, builder()->bool_(! *bool_));
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

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass constant_folder({.name = "constant_folding", .phase = optimizer::Phase::Phase1, .run = run});

} // namespace
