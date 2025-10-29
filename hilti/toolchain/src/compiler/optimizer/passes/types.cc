// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;

namespace {

struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    std::map<ID, bool> used;

    void done() final {
        if ( logger().isEnabled(logging::debug::OptimizerDetail) ) {
            HILTI_DEBUG(logging::debug::OptimizerDetail, "types:");
            for ( const auto& [id, used] : used )
                HILTI_DEBUG(logging::debug::OptimizerDetail, util::fmt("    %s: used=%d", id, used));
        }
    }

    void operator()(declaration::Field* n) final {
        const auto type_id = n->type()->type()->typeID();

        if ( ! type_id )
            return;

        // Record this type as used.
        used[type_id] = true;
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

        // Record the type if not already known. If the type is part of an external API record it as used.
        used.insert({type_id, n->linkage() == declaration::Linkage::Public});
    }

    void operator()(type::Name* n) final {
        auto* t = n->resolvedType();
        assert(t);

        if ( const auto& type_id = t->typeID() )
            // Record this type as used.
            used[type_id] = true;
    }

    void operator()(UnqualifiedType* n) final {
        if ( n->parent(2)->isA<declaration::Type>() )
            return;

        if ( const auto& type_id = n->typeID() )
            // Record this type as used.
            used[type_id] = true;
    }

    void operator()(expression::Name* n) final {
        auto* const type = optimizer()->innermostType(n->type());

        const auto& type_id = type->type()->typeID();

        if ( ! type_id )
            return;

        // Record this type as used.
        used[type_id] = true;
    }

    void operator()(declaration::Function* n) final {
        if ( auto* const decl = context()->lookup(n->linkedDeclarationIndex()) ) {
            // If this type is referenced by a function declaration it is used.
            used[decl->fullyQualifiedID()] = true;
        }
    }

    void operator()(expression::Type_* n) final {
        const auto type_id = n->typeValue()->type()->typeID();
        ;

        if ( ! type_id )
            return;

        // Record this type as used.
        used[type_id] = true;
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

    void operator()(declaration::Type* n) final {
        // We currently only handle type declarations for struct types or enum types.
        //
        // TODO(bbannier): Handle type aliases.
        if ( const auto& type = n->type(); ! (type->type()->isA<type::Struct>() || type->type()->isA<type::Enum>()) )
            return;

        const auto type_id = n->typeID();

        if ( ! type_id )
            return;

        if ( ! collector->used.at(type_id) ) {
            removeNode(n, "removing unused type");
            return;
        }
    }
};

optimizer::Result run(Optimizer* optimizer) {
    Collector collector(optimizer);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass types({.name = "types", .phase = optimizer::Phase::Phase1, .run = run});

} // namespace
