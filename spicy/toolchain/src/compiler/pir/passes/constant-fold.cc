// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cstdint>
#include <limits>
#include <optional>
#include <variant>

#include <spicy/compiler/detail/pir/passes/constant-fold.h>

using namespace spicy::detail::pir;
using namespace spicy::detail::pir::ir;

namespace {

std::optional<int64_t> constantValue(const Package& package, InstId id) {
    if ( ! package.isValid(id) )
        return {};

    const auto& inst = package.inst(id);
    if ( inst.opcode != Opcode::Constant )
        return {};

    if ( const auto* value = std::get_if<Int64Literal>(&inst.payload) )
        return value->value;

    return {};
}

std::optional<int64_t> checkedAdd(int64_t a, int64_t b) {
    constexpr auto max = std::numeric_limits<int64_t>::max();
    constexpr auto min = std::numeric_limits<int64_t>::min();

    if ( b >= 0 ? a > max - b : a < min - b )
        return {};

    return a + b;
}

} // namespace

namespace spicy::detail::pir::passes {

bool foldConstants(Package& package, FunctionId function) {
    if ( ! package.isValid(function) )
        return false;

    bool changed = false;

    const auto& fn = package.function(function);
    if ( ! package.isValid(fn.root_region) )
        return false;

    for ( auto block_id : package.region(fn.root_region).blocks ) {
        if ( ! package.isValid(block_id) )
            continue;

        auto insts = package.block(block_id).insts;

        for ( auto inst_id : insts ) {
            const auto& inst = package.inst(inst_id);
            if ( inst.opcode != Opcode::Add )
                continue;

            auto* schema = schemaFor(inst.opcode);
            if ( ! schema || inst.args.size() != schema->operandCount() )
                continue;

            auto lhs = constantValue(package, inst.args[0]);
            auto rhs = constantValue(package, inst.args[1]);
            if ( ! lhs || ! rhs )
                continue;

            auto sum = checkedAdd(*lhs, *rhs);
            if ( ! sum )
                continue;

            package.replaceInst(inst_id, Opcode::Constant, {}, InstPayload(Int64Literal{*sum}));
            changed = true;
        }
    }

    return changed;
}

} // namespace spicy::detail::pir::passes
