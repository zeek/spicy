// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>

using namespace hilti;
using namespace hilti::detail::optimizer;

struct TypeVisitor : OptimizerVisitor {
    using OptimizerVisitor::OptimizerVisitor;
    using OptimizerVisitor::operator();

    std::map<ID, bool> used;

    void collect(Node* node) override {
        stage = Stage::Collect;

        visitor::visit(*this, node);

        if ( logger().isEnabled(logging::debug::OptimizerCollect) ) {
            HILTI_DEBUG(logging::debug::OptimizerCollect, "types:");
            for ( const auto& [id, used] : used )
                HILTI_DEBUG(logging::debug::OptimizerCollect, util::fmt("    %s: used=%d", id, used));
        }
    }

    bool pruneDecls(Node* node) override {
        stage = Stage::PruneDecls;

        clearModified();
        visitor::visit(*this, node);

        return isModified();
    }

    void operator()(declaration::Field* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                const auto type_id = n->type()->type()->typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                used[type_id] = true;

                break;
            }
            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Type* n) final {
        // We currently only handle type declarations for struct types or enum types.
        //
        // TODO(bbannier): Handle type aliases.
        if ( const auto& type = n->type(); ! (type->type()->isA<type::Struct>() || type->type()->isA<type::Enum>()) )
            return;

        const auto type_id = n->typeID();

        if ( ! type_id )
            return;

        switch ( stage ) {
            case Stage::Collect:
                // Record the type if not already known. If the type is part of an external API record it as used.
                used.insert({type_id, n->linkage() == declaration::Linkage::Public});
                break;

            case Stage::PruneUses: break;
            case Stage::PruneDecls:
                if ( ! used.at(type_id) ) {
                    removeNode(n, "removing unused type");
                    return;
                }

                break;
        }
    }

    void operator()(type::Name* n) final {
        auto* t = n->resolvedType();
        assert(t);

        switch ( stage ) {
            case Stage::Collect: {
                if ( const auto& type_id = t->typeID() )
                    // Record this type as used.
                    used[type_id] = true;

                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(UnqualifiedType* n) final {
        if ( n->parent(2)->isA<declaration::Type>() )
            return;

        switch ( stage ) {
            case Stage::Collect: {
                if ( const auto& type_id = n->typeID() )
                    // Record this type as used.
                    used[type_id] = true;

                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(expression::Name* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                auto* const type = innermostType(n->type());

                const auto& type_id = type->type()->typeID();

                if ( ! type_id )
                    break;

                // Record this type as used.
                used[type_id] = true;

                break;
            }
            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(declaration::Function* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                if ( auto* const decl = context()->lookup(n->linkedDeclarationIndex()) ) {
                    // If this type is referenced by a function declaration it is used.
                    used[decl->fullyQualifiedID()] = true;
                    break;
                }
            }

            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }

    void operator()(expression::Type_* n) final {
        switch ( stage ) {
            case Stage::Collect: {
                const auto type_id = n->typeValue()->type()->typeID();
                ;

                if ( ! type_id )
                    break;

                // Record this type as used.
                used[type_id] = true;
                break;
            }

            case Stage::PruneUses:
            case Stage::PruneDecls:
                // Nothing.
                break;
        }
    }
};

static RegisterPass constant_folder(
    "types", {[](Builder* builder, const OperatorUses* op_uses) -> std::unique_ptr<OptimizerVisitor> {
                  return std::make_unique<TypeVisitor>(builder, hilti::logging::debug::Optimizer, op_uses);
              },
              1});
