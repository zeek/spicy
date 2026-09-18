// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/ir/printer.h>
#include <spicy/compiler/detail/pir/ir/reachability.h>

using hilti::util::fmt;

namespace spicy::detail::pir::ir {

namespace {

std::string_view opcodeName(Opcode opcode) {
    if ( auto* schema = schemaFor(opcode) )
        return schema->spelling;

    return "<unknown-opcode>";
}

std::string printOperand(InstId id) { return fmt("%%%u", id.index); }

std::string_view byteOrderName(ByteOrder order) {
    switch ( order ) {
        case ByteOrder::Little: return "little";
        case ByteOrder::Big: return "big";
        case ByteOrder::Network: return "network";
        case ByteOrder::Host: return "host";
    }

    return "<unknown-byte-order>";
}

// Absent for `std::monostate` (no payload); otherwise the payload's canonical printed form, to be
// joined alongside operands. A multi-field payload (e.g. `ReadIntegerPayload`) is already
// comma-joined internally so it reads as one further element in that outer join.
std::optional<std::string> renderPayload(const Package& package, const InstPayload& payload) {
    if ( const auto* lit = std::get_if<Int64Literal>(&payload) )
        return fmt("%d", lit->value);

    if ( const auto* arg = std::get_if<ArgumentPayload>(&payload) )
        return fmt("%u", arg->index);

    if ( const auto* tg = std::get_if<TupleGetPayload>(&payload) )
        return fmt("%u", tg->index);

    if ( const auto* ri = std::get_if<ReadIntegerPayload>(&payload) )
        return fmt("width=%u, signed=%s, byte_order=%s",
                   ri->width,
                   ri->signedness == Signedness::Signed ? "true" : "false",
                   byteOrderName(ri->byte_order));

    if ( const auto* up = std::get_if<UnitPayload>(&payload) ) {
        if ( ! package.isValid(up->unit) )
            return std::string("@<invalid-unit>");
        return fmt("@%%%u \"%s\"", up->unit.index, package.typeDecl(up->unit).name);
    }

    if ( const auto* fp = std::get_if<FieldPayload>(&payload) ) {
        if ( ! package.isValid(fp->field) )
            return std::string("@<invalid-field>");
        const auto& field = package.declaration(fp->field);
        if ( ! package.isValid(field.owner) )
            return fmt("@<invalid-unit>::%%%u \"%s\"", fp->field.index, field.name);
        return fmt("@%%%u \"%s\"::%%%u \"%s\"",
                   field.owner.index,
                   package.typeDecl(field.owner).name,
                   fp->field.index,
                   field.name);
    }

    return std::nullopt;
}

std::string printInst(const Package& package, InstId id) {
    const auto& inst = package.inst(id);

    std::string body{opcodeName(inst.opcode)};

    std::vector<std::string> tokens;
    for ( auto arg : inst.args )
        tokens.push_back(printOperand(arg));

    if ( auto payload_text = renderPayload(package, inst.payload) )
        tokens.push_back(std::move(*payload_text));

    for ( size_t i = 0; i < tokens.size(); ++i )
        body += (i == 0 ? " " : ", ") + tokens[i];

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

            return fmt("unit<@%%%u \"%s\">", t.declaration.index, package.typeDecl(t.declaration).name);
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

        // Step 2's procedural functions always have zero parameters; only print a parameter list
        // when there's one to show, so their exact canonical dump is unaffected.
        std::string parameters;
        for ( size_t p = 0; p < fn.parameters.size(); ++p )
            parameters += (p == 0 ? "" : ", ") + typeName(package, fn.parameters[p]);

        // Step 2's procedural functions are always `Normal` with no parser unit; only append the
        // kind/parser-unit suffix for a `Parser` function, so their exact canonical dump is
        // unaffected.
        std::string suffix;
        if ( fn.kind == FunctionKind::Parser ) {
            suffix = " [parser, unit=";
            suffix += package.isValid(fn.parser_unit) ?
                          fmt("@%%%u \"%s\"", fn.parser_unit.index, package.typeDecl(fn.parser_unit).name) :
                          std::string("@<invalid-unit>");
            suffix += "]";
        }

        if ( fn.parameters.empty() )
            out += fmt("function %%%u \"%s\" -> %s%s:\n",
                       function_id.index,
                       fn.name,
                       typeName(package, fn.result_type),
                       suffix);
        else
            out += fmt("function %%%u \"%s\" (%s) -> %s%s:\n",
                       function_id.index,
                       fn.name,
                       parameters,
                       typeName(package, fn.result_type),
                       suffix);

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
