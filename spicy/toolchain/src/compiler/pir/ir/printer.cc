// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <string_view>
#include <variant>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/reachability.h>

using hilti::util::fmt;

namespace spicy::detail::pir::ir {

namespace {

std::string_view opcodeName(Opcode opcode) {
    if ( auto schema = lookupSchema(opcode) )
        return schema->spelling;

    return "<unknown-opcode>";
}

std::string_view printType(const Package& package, TypeId type_id) {
    if ( ! package.isValid(type_id) )
        return "<invalid-type>";

    switch ( package.type(type_id).kind ) {
        case TypeKind::Void: return "void";
        case TypeKind::Int64: return "int64";
    }

    return "<unknown-type>";
}

std::string printOperand(InstId id) { return fmt("%%%u", id.index); }

std::string printInst(const Package& package, InstId id) {
    const auto& inst = package.inst(id);

    std::string body{opcodeName(inst.opcode)};

    if ( const auto* value = std::get_if<int64_t>(&inst.payload) )
        body += fmt(" %d", *value);

    for ( size_t i = 0; i < inst.args.size(); ++i )
        body += (i == 0 ? " " : ", ") + printOperand(inst.args[i]);

    body += fmt(" : %s", printType(package, inst.result_type));

    if ( inst.result_type != package.voidType() )
        return fmt("%s = %s", printOperand(id), body);

    return fmt("%s: %s", printOperand(id), body);
}

} // namespace

std::string print(const Package& package) {
    std::string out;

    for ( size_t i = 0; i < package.types().size(); ++i )
        out += fmt("type %%%zu: %s\n", i, printType(package, TypeId{static_cast<uint32_t>(i)}));

    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto function_id = FunctionId{static_cast<uint32_t>(i)};
        const auto& fn = package.function(function_id);
        out += fmt("function %%%u \"%s\" -> %s:\n", function_id.index, fn.name, printType(package, fn.result_type));

        if ( ! package.isValid(fn.root_region) ) {
            out += "  <invalid root region>\n";
            continue;
        }

        out += fmt("  region %%%u:\n", fn.root_region.index);

        for ( auto block_id : package.region(fn.root_region).blocks ) {
            out += fmt("    block %%%u:\n", block_id.index);

            if ( ! package.isValid(block_id) ) {
                out += "      <invalid block>\n";
                continue;
            }

            for ( auto inst_id : package.block(block_id).insts )
                out += "      " + printInst(package, inst_id) + "\n";
        }
    }

    auto reach = computeReachableIds(package);

    for ( size_t i = 0; i < package.regions().size(); ++i )
        if ( ! reach.regions.contains(static_cast<uint32_t>(i)) )
            out += fmt("orphan region %%%zu\n", i);

    for ( size_t i = 0; i < package.blocks().size(); ++i )
        if ( ! reach.blocks.contains(static_cast<uint32_t>(i)) )
            out += fmt("orphan block %%%zu\n", i);

    for ( size_t i = 0; i < package.instructions().size(); ++i )
        if ( ! reach.insts.contains(static_cast<uint32_t>(i)) )
            out += "orphan instruction " + printInst(package, InstId{static_cast<uint32_t>(i)}) + "\n";

    return out;
}

} // namespace spicy::detail::pir::ir
