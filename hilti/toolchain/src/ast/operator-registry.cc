// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/operator-registry.h>
#include <hilti/compiler/context.h>

using namespace hilti;
using namespace hilti::operator_;

namespace hilti::logging::debug {
inline const DebugStream Operator("operator");
} // namespace hilti::logging::debug

void Registry::register_(std::unique_ptr<Operator> op) { _pending.push_back(std::move(op)); }

void Registry::initPending(Builder* builder) {
    if ( _pending.empty() )
        return;

    HILTI_DEBUG(hilti::logging::debug::Operator,
                hilti::util::fmt("%d operators pending to be resolved for initialization", _pending.size()));

    for ( auto i = _pending.begin(); i != _pending.end(); ) {
        auto current = i++;
        auto&& op = *current;

        auto x = op->init(builder, builder->context()->root());
        if ( ! x )
            continue;

        if ( (op->kind() != Kind::Call || op->isBuiltIn()) && op->kind() != Kind::MemberCall ) {
            assert(! _operators_by_name.contains(op->name()));
            _operators_by_name[op->name()] = op.get();
        }

        if ( op->hasOperands() ) { // only register if to be instantiated by the resolver through its operands
            _operators_by_kind[op->kind()].push_back(op.get());
            if ( op->kind() == Kind::MemberCall ) {
                const auto& id = op->signature().operands->op1()->type()->type()->as<type::Member>()->id();
                _operators_by_method[id].push_back(op.get());
            }

            if ( op->kind() == Kind::Call && op->isBuiltIn() ) {
                if ( auto* member = op->signature().operands->op0()->type()->type()->tryAs<type::Member>() )
                    _operators_by_builtin_function[member->id()].push_back(op.get());
                else
                    _operators_by_builtin_function[ID()].push_back(op.get());
            }
        }

        HILTI_DEBUG(hilti::logging::debug::Operator,
                    hilti::util::fmt("initialized operator %s (%s)", op->name(), op->print()));

        _operators.push_back(std::move(op));
        _pending.erase(current);
    }
}

void Registry::debugEnforceBuiltInsAreResolved(Builder* builder) const {
    if ( ! builder->options().import_standard_modules )
        // It's expected that can resolve all builtins.
        return;

    bool abort = false;

    for ( const auto& op : _pending ) {
        if ( ! op->isBuiltIn() )
            continue;

        if ( ! abort )
            logger().error("[Internal Error] The following builtin operators were not resolved:");

        logger().error(util::fmt("    %s", op->name()));
        abort = true;
    }

    if ( abort )
        logger().fatalError("Aborting.");
}


std::pair<bool, std::optional<std::vector<const Operator*>>> Registry::functionCallCandidates(
    const expression::UnresolvedOperator* op) {
    assert(op->operands().size() > 0);

    // Try built-in function operators first, they override anything found
    // by scope lookup. (The validator will reject functions with a name
    // matching a built-in one anyway.)
    if ( auto* member = op->op0()->tryAs<expression::Member>() ) {
        auto candidates = byBuiltinFunctionID(member->id());
        if ( ! candidates.empty() )
            return std::make_pair(true, std::move(candidates));
    }

    // If it's a name expression, return any functions that we find through
    // scope lookup.
    if ( auto* callee = op->op0()->tryAs<expression::Name>() ) {
        std::vector<const Operator*> candidates;
        for ( const Node* n = op; n; n = n->parent() ) {
            if ( ! n->scope() )
                continue;

            for ( const auto& r : n->scope()->lookupAll(callee->id()) ) {
                auto* d = r.node->tryAs<declaration::Function>();
                if ( ! d )
                    // It's ok to refer to types for some constructor
                    // expressions.
                    continue;

                if ( r.external && ! d->isPublic() )
                    return std::make_pair(false, std::nullopt);

                if ( d->operator_() && d->operator_()->isInitialized() ) // not necessarily initialized yet
                    candidates.emplace_back(d->operator_());
            }

            if ( n->isA<declaration::Module>() )
                break;
        }

        if ( ! candidates.empty() )
            return std::make_pair(true, std::move(candidates));
    }

    // If all operands are fully-resolved, return any built-in function
    // operators that aren't hardcoding a name.
    if ( op->areOperandsUnified() )
        return std::make_pair(true, _operators_by_builtin_function[ID()]);

    // Nothing found.
    return std::make_pair(true, std::vector<const Operator*>{});
}

void Registry::clear() {
    _pending.clear();
    _operators.clear();
    _operators_by_name.clear();
    _operators_by_kind.clear();
    _operators_by_builtin_function.clear();
    _operators_by_method.clear();
}
