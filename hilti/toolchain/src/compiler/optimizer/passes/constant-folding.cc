// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>

using namespace hilti;
using namespace hilti::detail::optimizer;

struct ConstantFoldingVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;
    using OptimizerVisitor::operator();

    std::map<ID, bool> constants;

    void collect(Node* node) override {
        stage = Stage::Collect;

        visitor::visit(*this, node);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "constants:");
            std::vector<std::string> xs;
            for ( const auto& [id, value] : constants )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s: value=%d", id, value));
        }
    }

    bool pruneUses(Node* node) override {
        stage = Stage::PruneUses;

        bool any_modification = false;

        while ( true ) {
            clearModified();
            visitor::visit(*this, node);

            if ( ! isModified() )
                break;

            any_modification = true;
        }

        return any_modification;
    }

    // XXX

    void operator()(declaration::Constant* n) final {
        if ( ! n->type()->type()->isA<type::Bool>() )
            return;

        const auto& id = n->fullyQualifiedID();
        assert(id);

        switch ( stage ) {
            case Stage::Collect: {
                if ( auto* ctor = n->value()->tryAs<expression::Ctor>() )
                    if ( auto* bool_ = ctor->ctor()->tryAs<ctor::Bool>() )
                        constants[id] = bool_->value();

                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls: break;
        }
    }

    void operator()(expression::Name* n) final {
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: return;
            case Stage::PruneUses: {
                auto* decl = n->resolvedDeclaration();
                if ( ! decl )
                    return;

                const auto& id = decl->fullyQualifiedID();
                assert(id);

                if ( const auto& constant = constants.find(id); constant != constants.end() ) {
                    if ( n->type()->type()->isA<type::Bool>() ) {
                        replaceNode(n, builder()->bool_((constant->second)), "inlining constant");
                        return;
                    }
                }
            }
        }
    }

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
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: return;
            case Stage::PruneUses: {
                if ( auto bool_ = tryAsBoolLiteral(n->condition()) ) {
                    if ( auto* else_ = n->false_() ) {
                        if ( ! bool_.value() ) {
                            replaceNode(n, else_);
                            return;
                        }
                        else {
                            replaceNode(n, builder()->statementIf(n->init(), n->condition(), n->true_(), nullptr));
                            return;
                        }
                    }
                    else {
                        if ( ! bool_.value() ) {
                            removeNode(n);
                            return;
                        }
                        else {
                            replaceNode(n, n->true_());
                            return;
                        }
                    }

                    return;
                };
            }
        }
    }

    void operator()(expression::Ternary* n) final {
        switch ( stage ) {
            case OptimizerVisitor::Stage::Collect:
            case OptimizerVisitor::Stage::PruneDecls: return;
            case OptimizerVisitor::Stage::PruneUses: {
                if ( auto bool_ = tryAsBoolLiteral(n->condition()) ) {
                    if ( *bool_ )
                        replaceNode(n, n->true_());
                    else
                        replaceNode(n, n->false_());

                    return;
                }
            }
        }
    }

    void operator()(expression::LogicalOr* n) final {
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: break;
            case Stage::PruneUses: {
                auto lhs = tryAsBoolLiteral(n->op0());
                auto rhs = tryAsBoolLiteral(n->op1());

                if ( lhs && rhs ) {
                    replaceNode(n, builder()->bool_(lhs.value() || rhs.value()));
                    return;
                }
            }
        };
    }

    void operator()(expression::LogicalAnd* n) final {
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: break;
            case Stage::PruneUses: {
                auto lhs = tryAsBoolLiteral(n->op0());
                auto rhs = tryAsBoolLiteral(n->op1());

                if ( lhs && rhs ) {
                    replaceNode(n, builder()->bool_(lhs.value() && rhs.value()));
                    return;
                }
            }
        };
    }

    void operator()(expression::LogicalNot* n) final {
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: break;
            case Stage::PruneUses: {
                if ( auto op = tryAsBoolLiteral(n->expression()) ) {
                    replaceNode(n, builder()->bool_(! op.value()));
                    return;
                }
            }
        };
    }

    void operator()(statement::While* x) final {
        switch ( stage ) {
            case Stage::Collect:
            case Stage::PruneDecls: return;
            case Stage::PruneUses: {
                const auto& cond = x->condition();
                if ( ! cond )
                    return;

                const auto val = tryAsBoolLiteral(cond);
                if ( ! val )
                    return;

                // If the `while` condition is true we never run the `else` block.
                if ( *val && x->else_() ) {
                    recordChange(x, "removing else block of while loop with true condition");
                    x->removeElse(context());
                    return;
                }

                // If the `while` condition is false we never enter the loop, and
                // run either the `else` block if it is present or nothing.
                else if ( ! *val ) {
                    if ( x->else_() )
                        replaceNode(x, x->else_(), "replacing while loop with its else block");
                    else {
                        recordChange(x, "removing while loop with false condition");
                        x->parent()->removeChild(x->as<Node>());
                    }

                    return;
                }

                return;
            }
        }
    }
};

static RegisterPass constant_folder(
    "constant_folding", {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
                             return std::make_unique<ConstantFoldingVisitor>(builder, hilti::logging::debug::Optimizer,
                                                                             op_uses);
                         },
                         1});
