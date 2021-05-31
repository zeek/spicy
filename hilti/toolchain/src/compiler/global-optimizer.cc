// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/global-optimizer.h"

#include <optional>
#include <unordered_set>
#include <utility>

#include <hilti/ast/ctors/default.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/struct.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>

namespace hilti {

using ModuleID = GlobalOptimizer::ModuleID;
using StructID = GlobalOptimizer::StructID;
using FieldID = GlobalOptimizer::FieldID;

namespace logging::debug {
inline const DebugStream GlobalOptimizer("global-optimizer");
} // namespace logging::debug

enum class Stage { COLLECT, PRUNE };

template<typename T>
std::optional<std::pair<ModuleID, StructID>> typeID(T&& x) {
    auto id = x.typeID();
    if ( ! id )
        return {};

    return {{id->sub(-2), id->sub(-1)}};
}

struct Visitor : hilti::visitor::PreOrder<bool, Visitor> {
    Visitor(GlobalOptimizer::Hooks* hooks) : _hooks(hooks) {}

    static void removeNode(position_t& p) { p.node = node::none; }

    Stage _stage = Stage::COLLECT;

    void collect(Node& node) {
        _stage = Stage::COLLECT;

        for ( auto i : this->walk(&node) )
            dispatch(i);
    }

    void prune(Node& node) {
        _stage = Stage::PRUNE;

        for ( auto&& [hook_id, uses] : *_hooks ) {
            // Linker joins are implemented via functions, so if we remove all
            // functions data dependencies (e.g., needed for subunits) might
            // get broken. Leave at least one function in unit so it gets emitted.
            //
            // TODO(bbannier): Explicitly express data dependencies in joins,
            // see https://github.com/zeek/spicy/issues/918.
            if ( std::get<2>(hook_id) == std::string("__str__") ) {
                uses.defined = true;
                continue;
            }
        }

        while ( true ) {
            bool modified = false;
            for ( auto i : this->walk(&node) ) {
                if ( auto x = dispatch(i) )
                    modified = modified || *x;
            }

            if ( ! modified )
                break;
        }
    }

    // TODO(bbannier): Also collect global hooks (outside of a struct) as well.

    result_t operator()(const type::struct_::Field& x, position_t p) {
        if ( auto type_ = x.type().tryAs<type::Function>(); ! type_ )
            return false;

        auto field_id = x.id();

        auto struct_type = typeID(p.parent().as<type::Struct>());
        if ( ! struct_type )
            return false;

        auto&& [module_id, struct_id] = *struct_type;

        auto type_ = p.findParent<declaration::Type>();
        bool is_cxx = type_ && AttributeSet::find(type_->get().attributes(), "&cxxname");

        auto ids = std::make_tuple(module_id, struct_id, field_id);

        switch ( _stage ) {
            case Stage::COLLECT: {
                auto fn = x.childsOfType<Function>();
                assert(fn.size() <= 1);

                bool is_always_emit = ! fn.empty() && AttributeSet::find(fn.front().attributes(), "&always-emit");

                // Record a declaration for this member.
                (*_hooks)[ids].declared = true;

                // If the member declaration is marked `&always-emit` mark it as implemented.
                if ( is_always_emit )
                    (*_hooks)[ids].defined = true;

                // If the member declaration includes a body mark it as implemented.
                if ( ! fn.empty() && fn.front().body() )
                    (*_hooks)[ids].defined = true;

                // If the unit is wrapped in a type with a `&cxxname`
                // attribute its members are defined in C++ as well.
                if ( is_cxx )
                    (*_hooks)[ids].defined = true;

                break;
            }

            case Stage::PRUNE: {
                // Remove hooks without implementation.
                if ( auto hook = _hooks->at(ids); ! hook.defined ) {
                    HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                util::fmt("removing field for unused hook %s::%s::%s", module_id, struct_id, field_id));
                    removeNode(p);

                    return true;
                }

                break;
            }
        }

        return false;
    }

    result_t operator()(const declaration::Function& x, position_t p) {
        switch ( _stage ) {
            case Stage::COLLECT: {
                auto module_id = x.id().sub(-3);
                if ( module_id.empty() ) {
                    // HILTI hook functions do not include the name their module in their ID.
                    if ( auto module = p.findParent<Module>() )
                        module_id = module->get().id();
                }

                auto struct_id = x.id().sub(-2);
                auto field_id = x.id().sub(-1);

                if ( module_id.empty() || struct_id.empty() ||
                     field_id.empty() ) // Declaration does not look like for a member.
                    return false;

                // Record this hook if it is not already known.
                auto hook_id = std::make_tuple(std::move(module_id), std::move(struct_id), std::move(field_id));
                (*_hooks)[hook_id].defined = true;
                break;
            }

            case Stage::PRUNE:
                // Nothing.
                break;
        }

        return false;
    }

    result_t operator()(const operator_::struct_::MemberCall& x, position_t p) {
        if ( ! x.hasOp1() )
            return false;

        assert(x.hasOp0());

        auto struct_type = typeID(x.op0().type());
        if ( ! struct_type )
            return false;

        auto&& [module_id, struct_id] = *struct_type;

        auto&& member = x.op1().tryAs<expression::Member>();
        if ( ! member )
            return false;

        auto hook_id = std::make_tuple(module_id, struct_id, member->id());

        switch ( _stage ) {
            case Stage::COLLECT: {
                (*_hooks)[hook_id].referenced = true;
                return false;
            }

            case Stage::PRUNE: {
                // Replace call node referencing unimplemented hook with default value.
                if ( auto hook = _hooks->at(hook_id); ! hook.defined ) {
                    if ( auto fn = member->memberType()->tryAs<type::Function>() ) {
                        HILTI_DEBUG(logging::debug::GlobalOptimizer,
                                    util::fmt("replacing call to unimplemented hook %s::%s::%s with default value",
                                              module_id, struct_id, member->id()));

                        p.node = Expression(expression::Ctor(ctor::Default(fn->result().type())));

                        return true;
                    }
                }

                break;
            }
        }

        return false;
    }

    GlobalOptimizer::Hooks* _hooks = nullptr;
};

void GlobalOptimizer::run() {
    util::timing::Collector _("hilti/compiler/global-optimizer");

    // Create a full list of units to run on. This includes both the units
    // explicitly passed on construction as well as their dependencies.
    auto units = [&]() {
        // We initially store the list as a `set` to ensure uniqueness, but
        // convert to a `vector` so we can mutate entries while iterating.
        auto NodeRefCmp = [](const NodeRef& lhs, const NodeRef& rhs) { return lhs->identity() < rhs->identity(); };
        std::set<NodeRef, decltype(NodeRefCmp)> units(NodeRefCmp);

        for ( auto& unit : *_units ) {
            units.insert(NodeRef(unit.imported(unit.id())));

            for ( auto&& dep : _ctx->lookupDependenciesForModule(unit.id()) )
                units.insert(NodeRef(unit.imported(dep.index.id)));
        }

        return std::vector<NodeRef>{units.begin(), units.end()};
    }();

    for ( auto& unit : units )
        Visitor(&_hooks).collect(*unit);

    for ( auto& unit : units )
        Visitor(&_hooks).prune(*unit);
}

} // namespace hilti
