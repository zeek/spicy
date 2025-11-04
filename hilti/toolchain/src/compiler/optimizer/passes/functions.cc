// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <numeric>

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;

namespace {

struct Collector : public optimizer::visitor::Collector {
    using optimizer::visitor::Collector::Collector;

    struct Uses {
        bool hook = false;
        bool defined = false;
        bool referenced = false;
    };

    // Lookup table for feature name -> required.
    using Features = std::map<std::string, bool>;

    // Lookup table for typename -> features.
    std::map<ID, Features> features;

    std::map<ID, Uses> data;

    // TODO: Do not override run here.
    void run() override {
        // Helper to compute the total number of collected features over all types.
        auto num_features = [&]() {
            return std::accumulate(features.begin(), features.end(), 0U,
                                   [](auto acc, auto&& f) { return acc + f.second.size(); });
        };

        // Whether a function can be elided depends on which features are active. Since we discover features as we visit
        // the AST (which likely contains multiple modules), we need to iterate until we have collected all features.
        while ( true ) {
            const auto num_features_0 = num_features();

            hilti::visitor::visit(*this, context()->root());

            if ( logger().isEnabled(logging::debug::OptimizerDetail) ) {
                HILTI_DEBUG(logging::debug::OptimizerDetail, "functions:");
                for ( const auto& [id, uses] : data )
                    HILTI_DEBUG(logging::debug::OptimizerDetail,
                                util::fmt("    %s: defined=%d referenced=%d hook=%d", id, uses.defined, uses.referenced,
                                          uses.hook));
            }

            const auto num_features_1 = num_features();

            // We have seen everything since no new features were found.
            if ( num_features_0 == num_features_1 )
                break;
        }
    }

    void operator()(declaration::Field* n) final {
        if ( ! n->type()->type()->isA<type::Function>() )
            return;

        if ( ! n->parent()->isA<type::Struct>() )
            return;

        const auto& function_id = n->fullyQualifiedID();
        assert(function_id);

        auto& function = data[function_id];

        auto fn = n->childrenOfType<Function>();
        assert(fn.size() <= 1);

        // If the member declaration is marked `&always-emit` mark it as implemented.
        if ( n->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
            function.defined = true;

        // If the member declaration includes a body mark it as implemented.
        if ( ! fn.empty() && (*fn.begin())->body() )
            function.defined = true;

        // If the unit is wrapped in a type with a `&cxxname`
        // attribute its members are defined in C++ as well.
        auto* type_ = n->parent<declaration::Type>();

        if ( type_ && type_->attributes()->find(hilti::attribute::kind::Cxxname) )
            function.defined = true;

        if ( n->type()->type()->as<type::Function>()->flavor() == type::function::Flavor::Hook )
            function.hook = true;

        if ( auto* type = type_ ) {
            for ( const auto& requirement : n->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                const auto& requirement_ = requirement->valueAsString();
                const auto& feature = *requirement_;

                // If no feature constants were collected yet, reschedule us for the next collection pass.
                //
                // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                // constant, so eventually at this point we will see at least one feature constant.
                if ( features.empty() )
                    return;

                auto it = features.find(type->type()->type()->typeID());
                if ( it == features.end() || ! it->second.contains(feature) )
                    // This feature requirement has not yet been collected.
                    continue;

                function.referenced = function.referenced || it->second.at(feature);
            }
        }
    }

    void operator()(declaration::Function* n) final {
        auto function_id = n->functionID(context());

        // Record this function if it is not already known.
        auto& function = data[function_id];

        const auto& fn = n->function();

        // If the declaration contains a function with a body mark the function as defined.
        if ( fn->body() )
            function.defined = true;

        // If the declaration has a `&cxxname` it is defined in C++.
        else if ( fn->attributes()->find(hilti::attribute::kind::Cxxname) )
            function.defined = true;

        // If the member declaration is marked `&always-emit` mark it as referenced.
        if ( fn->attributes()->find(hilti::attribute::kind::AlwaysEmit) )
            function.referenced = true;

        // If the function is public mark is as referenced.
        if ( n->linkage() == declaration::Linkage::Public )
            function.referenced = true;

        // For implementation of methods check whether the method
        // should only be emitted when certain features are active.
        if ( auto* decl = context()->lookup(n->linkedDeclarationIndex()) ) {
            for ( const auto& requirement : fn->attributes()->findAll(hilti::attribute::kind::NeededByFeature) ) {
                const auto& requirement_ = requirement->valueAsString();
                const auto& feature = *requirement_;

                // If no feature constants were collected yet, reschedule us for the next collection pass.
                //
                // NOTE: If we emit a `&needed-by-feature` attribute we also always emit a matching feature
                // constant, so eventually at this point we will see at least one feature constant.
                if ( features.empty() ) {
                    return;
                }

                auto it = features.find(decl->fullyQualifiedID());
                if ( it == features.end() || ! it->second.contains(feature) ) {
                    // This feature requirement has not yet been collected.
                    continue;
                }

                // Mark the function as referenced if it is needed by an active feature.
                function.referenced = function.referenced || it->second.at(feature);
            }
        }

        if ( fn->ftype()->flavor() == type::function::Flavor::Hook )
            function.hook = true;

        auto* const decl = context()->lookup(n->linkedDeclarationIndex());

        switch ( fn->ftype()->callingConvention() ) {
            case type::function::CallingConvention::ExternNoSuspend:
            case type::function::CallingConvention::Extern: {
                // If the declaration is `extern` and the unit is `public`, the function
                // is part of an externally visible API and potentially used elsewhere.

                if ( decl )
                    function.referenced = function.referenced || decl->linkage() == declaration::Linkage::Public;
                else
                    function.referenced = true;

                break;
            }
            case type::function::CallingConvention::Standard:
                // Nothing.
                break;
        }

        switch ( n->linkage() ) {
            case declaration::Linkage::PreInit:
            case declaration::Linkage::Init:
                // If the function is pre-init or init it could get
                // invoked by the driver and should not be removed.
                function.referenced = true;
                break;
            case declaration::Linkage::Private:
            case declaration::Linkage::Public:
                // Nothing.
                break;
            case declaration::Linkage::Struct: {
                // If this is a method declaration check whether the type it referred
                // to is still around; if not mark the function as an unreferenced
                // non-hook so it gets removed for both plain methods and hooks.
                if ( ! decl ) {
                    function.referenced = false;
                    function.hook = false;
                }

                break;
            }
        }
    }

    void operator()(operator_::struct_::MemberCall* n) final {
        if ( ! n->hasOp1() )
            return;

        assert(n->hasOp0());

        auto* type = n->op0()->type();

        auto* struct_ = type->type()->tryAs<type::Struct>();
        if ( ! struct_ )
            return;

        const auto& member = n->op1()->tryAs<expression::Member>();
        if ( ! member )
            return;

        auto* field = struct_->field(member->id());
        if ( ! field )
            return;

        const auto& function_id = field->fullyQualifiedID();

        if ( ! function_id )
            return;

        auto& function = data[function_id];

        function.referenced = true;
    }

    void operator()(operator_::function::Call* n) final {
        if ( ! n->hasOp0() )
            return;

        auto* decl = n->op0()->as<expression::Name>()->resolvedDeclaration();
        if ( ! decl )
            return;

        const auto& function_id = decl->fullyQualifiedID();
        assert(function_id);

        auto& function = data[function_id];

        function.referenced = true;
    }

    void operator()(declaration::Constant* n) final {
        std::optional<bool> value;
        if ( auto* ctor = n->value()->tryAs<expression::Ctor>() )
            if ( auto* bool_ = ctor->ctor()->tryAs<ctor::Bool>() )
                value = bool_->value();

        if ( ! value )
            return;

        const auto& id = n->id();

        const auto& id_feature = optimizer()->idFeatureFromConstant(n->id());
        if ( ! id_feature )
            return;

        const auto& [type_id, feature] = *id_feature;

        // We only work on feature flags.
        if ( ! optimizer()->isFeatureFlag(id) )
            return;

        features[type_id].insert({feature, *value});
    }
};

struct Mutator : public optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer, const Collector* collector)
        : optimizer::visitor::Mutator(optimizer), collector(collector) {}

    const Collector* collector = nullptr;

    void operator()(declaration::Field* n) final {
        if ( ! n->type()->type()->isA<type::Function>() )
            return;

        if ( ! n->parent()->isA<type::Struct>() )
            return;

        const auto& function_id = n->fullyQualifiedID();
        assert(function_id);

        const auto& function = collector->data.at(function_id);

        // Remove function methods without implementation.
        if ( ! function.defined && ! function.referenced ) {
            HILTI_DEBUG(logging::debug::Optimizer, util::fmt("removing field for unused method %s", function_id));
            removeNode(n);
            return;
        }
    }

    void operator()(declaration::Function* n) final {
        auto function_id = n->functionID(context());

        const auto& function = collector->data.at(function_id);

        if ( function.hook && ! function.defined ) {
            removeNode(n, "removing declaration for unused hook function");
            return;
        }

        if ( ! function.hook && ! function.referenced ) {
            removeNode(n, "removing declaration for unused function");
            return;
        }
    }

    void operator()(operator_::struct_::MemberCall* n) final {
        if ( ! n->hasOp1() )
            return;

        assert(n->hasOp0());

        auto* type = n->op0()->type();

        auto* struct_ = type->type()->tryAs<type::Struct>();
        if ( ! struct_ )
            return;

        const auto& member = n->op1()->tryAs<expression::Member>();
        if ( ! member )
            return;

        auto* field = struct_->field(member->id());
        if ( ! field )
            return;

        const auto& function_id = field->fullyQualifiedID();

        if ( ! function_id )
            return;

        const auto& function = collector->data.at(function_id);

        // Replace call node referencing unimplemented member function with default value.
        if ( ! function.defined ) {
            if ( n->op0()->type()->type()->isA<type::Struct>() )
                replaceNode(n, builder()->expressionCtor(builder()->ctorDefault(n->result()->type())),
                            "replacing call to unimplemented method with default value");
            return;
        }
    }

    void operator()(operator_::function::Call* n) final {
        if ( ! n->hasOp0() )
            return;

        auto* decl = n->op0()->as<expression::Name>()->resolvedDeclaration();
        if ( ! decl )
            return;

        const auto& function_id = decl->fullyQualifiedID();
        assert(function_id);

        const auto& function = collector->data.at(function_id);

        // Replace call node referencing unimplemented hook with default value.
        if ( function.hook && ! function.defined ) {
            if ( auto* fn = decl->tryAs<declaration::Function>() ) {
                replaceNode(n,
                            builder()->expressionCtor(
                                builder()->ctorDefault(fn->function()->ftype()->result()->type())),
                            "replacing call to unimplemented function with default value");
                return;
            }
        }
    }
};

optimizer::Result run(Optimizer* optimizer) {
    Collector collector(optimizer);
    collector.run();

    return Mutator(optimizer, &collector).run();
}

optimizer::RegisterPass functions({.name = "functions",
                                   .phase = optimizer::Phase::Phase1,
                                   .requires_afterwards = optimizer::Requirements::ScopeBuilder |
                                                          optimizer::Requirements::TypeUnifier |
                                                          optimizer::Requirements::Coercer,
                                   .run = run});

} // namespace
