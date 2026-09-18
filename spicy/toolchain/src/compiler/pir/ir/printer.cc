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

std::string printOperand(InstId id) { return fmt("%%%u", id.index); }

std::string printInst(const Package& package, InstId id) {
    const auto& inst = package.inst(id);

    std::string body{opcodeName(inst.opcode)};

    if ( const auto* value = std::get_if<int64_t>(&inst.payload) )
        body += fmt(" %d", *value);

    for ( size_t i = 0; i < inst.args.size(); ++i )
        body += (i == 0 ? " " : ", ") + printOperand(inst.args[i]);

    body += fmt(" : %s", typeName(package, inst.result_type));

    if ( inst.result_type != package.voidType() )
        return fmt("%s = %s", printOperand(id), body);

    return fmt("%s: %s", printOperand(id), body);
}

} // namespace

std::string typeName(const Package& package, TypeId type_id) {
    if ( ! package.isValid(type_id) )
        return "<invalid-type>";

    const auto& t = package.type(type_id);
    switch ( t.kind ) {
        case TypeKind::Void: return "void";
        case TypeKind::Int64: return "int64";
        case TypeKind::UInt8: return "uint8";
        case TypeKind::ParserState: return "parser.state";

        case TypeKind::Unit: {
            if ( ! package.isValid(t.declaration) )
                return "unit<<invalid-decl>>";

            return fmt("unit<%s>", package.typeDecl(t.declaration).name);
        }

        case TypeKind::Tuple: {
            std::string out = "tuple<";
            for ( size_t i = 0; i < t.type_arguments.size(); ++i )
                out += (i == 0 ? "" : ", ") + typeName(package, t.type_arguments[i]);
            out += '>';
            return out;
        }
    }

    return "<unknown-type>";
}

std::string print(const Package& package) {
    std::string out;

    for ( size_t i = 0; i < package.types().size(); ++i )
        out += fmt("type %%%zu: %s\n", i, typeName(package, TypeId{static_cast<uint32_t>(i)}));

    for ( size_t i = 0; i < package.typeDecls().size(); ++i ) {
        auto decl_id = TypeDeclId{static_cast<uint32_t>(i)};
        const auto& decl = package.typeDecl(decl_id);
        out += fmt("unit %%%zu \"%s\":\n", i, decl.name);

        for ( auto field_id : decl.fields ) {
            if ( ! package.isValid(field_id) ) {
                out += "  <invalid field>\n";
                continue;
            }

            const auto& field = package.declaration(field_id);
            out += fmt("  field %%%u \"%s\" : %s\n", field_id.index, field.name, typeName(package, field.type));
        }
    }

    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto function_id = FunctionId{static_cast<uint32_t>(i)};
        const auto& fn = package.function(function_id);
        out += fmt("function %%%u \"%s\" -> %s:\n", function_id.index, fn.name, typeName(package, fn.result_type));

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

    for ( const auto& root : package.parserRoots() )
        out += fmt("parser root: unit %%%u -> function %%%u\n", root.unit.index, root.function.index);

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
