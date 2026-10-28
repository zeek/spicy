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
    if ( const auto* schema = schemaFor(opcode) )
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
        return fmt(R"(@%%%u "%s"::%%%u "%s")",
                   field.owner.index,
                   package.typeDecl(field.owner).name,
                   fp->field.index,
                   field.name);
    }

    if ( const auto* child = std::get_if<FunctionPayload>(&payload) )
        return fmt("@function %u", child->function.index);

    if ( const auto* foreign = std::get_if<ForeignFunctionPayload>(&payload) ) {
        if ( ! package.isValid(foreign->function) )
            return std::string("@foreign <invalid-function>");
        return fmt("@foreign %%%u \"%s\"", foreign->function.index, package.foreignFunction(foreign->function).name);
    }

    if ( const auto* bytes = std::get_if<ReadBytesPayload>(&payload) )
        return fmt("length=%u", bytes->length);

    if ( const auto* boolean = std::get_if<BoolLiteral>(&payload) )
        return std::string(boolean->value ? "true" : "false");

    if ( const auto* string = std::get_if<StringLiteral>(&payload) )
        return fmt("\"%s\"", string->value);

    if ( const auto* branch = std::get_if<BranchPayload>(&payload) )
        return fmt("then %%%u, else %%%u", branch->then_block.index, branch->else_block.index);
    if ( const auto* jump = std::get_if<JumpPayload>(&payload) )
        return fmt("%%%u", jump->target.index);
    if ( const auto* bytes = std::get_if<BytesLiteral>(&payload) )
        return fmt("b\"%s\"", bytes->value);

    return std::nullopt;
}

// A foreign formal as written in a declaration: a value's type, or the generic formal its convention names.
std::string foreignParameterName(const Package& package, const ForeignParameter& parameter) {
    switch ( parameter.argument ) {
        case ForeignArgument::Value: return typeName(package, parameter.type);
        case ForeignArgument::TypeInfo: return "any";
        case ForeignArgument::AnyPointer: return "any &cxx-any-as-ptr";
        case ForeignArgument::AnyTuple: return "tuple<*>";
    }

    return "<unknown-argument>";
}

std::string printInst(const Package& package, InstId id) {
    const auto& inst = package.inst(id);

    std::string body{opcodeName(inst.opcode)};

    std::vector<std::string> tokens;
    tokens.reserve(inst.args.size());
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
        case TypeKind::UInt64: return "uint64";
        case TypeKind::Bytes: return "bytes";
        case TypeKind::ParserState: return "parser.state";
        case TypeKind::Bool: return "bool";
        case TypeKind::String: return "string";

        case TypeKind::Vector:
            return t.type_arguments.size() == 1 ? fmt("vector<%s>", typeName(package, t.type_arguments[0])) :
                                                  "vector<<invalid-type>>";

        case TypeKind::Unit: {
            if ( ! package.isValid(t.declaration) )
                return "unit<<invalid-decl>>";

            return fmt("unit<@%%%u \"%s\">", t.declaration.index, package.typeDecl(t.declaration).name);
        }

        case TypeKind::Opaque: {
            if ( ! package.isValid(t.declaration) )
                return "opaque<<invalid-decl>>";

            return fmt("opaque<@%%%u \"%s\">", t.declaration.index, package.typeDecl(t.declaration).name);
        }

        case TypeKind::Place:
            return t.type_arguments.size() == 1 ? fmt("place<%s>", typeName(package, t.type_arguments[0])) :
                                                  "place<<invalid-type>>";

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

    auto print_region = [&](auto&& self, RegionId region_id, const std::string& indent) -> void {
        out += fmt("%sregion %%%u:\n", indent, region_id.index);
        if ( ! package.isValid(region_id) ) {
            out += indent + "  <invalid region>\n";
            return;
        }
        for ( auto block_id : package.region(region_id).blocks ) {
            out += fmt("%s  block %%%u:\n", indent, block_id.index);
            if ( ! package.isValid(block_id) ) {
                out += indent + "    <invalid block>\n";
                continue;
            }
            for ( auto inst_id : package.block(block_id).insts ) {
                if ( ! package.isValid(inst_id) ) {
                    out += indent + "    <invalid instruction>\n";
                    continue;
                }
                out += indent + "    " + printInst(package, inst_id) + "\n";
                for ( auto child : package.inst(inst_id).regions )
                    self(self, child, indent + "      ");
            }
        }
    };

    for ( size_t i = 0; i < package.types().size(); ++i )
        out += fmt("type %%%zu: %s\n", i, typeName(package, TypeId{static_cast<uint32_t>(i)}));

    for ( size_t i = 0; i < package.typeDecls().size(); ++i ) {
        auto decl_id = TypeDeclId{static_cast<uint32_t>(i)};
        const auto& decl = package.typeDecl(decl_id);
        if ( decl.kind == TypeDeclKind::Opaque ) {
            out += fmt("opaque type %%%zu \"%s\" (native \"%s\")\n",
                       i,
                       decl.name,
                       decl.opaque ? decl.opaque->cxx_name : std::string());
            continue;
        }

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

    for ( size_t i = 0; i < package.foreignFunctions().size(); ++i ) {
        const auto& fn = package.foreignFunction(ForeignFunctionId{static_cast<uint32_t>(i)});
        std::string parameters;
        for ( size_t p = 0; p < fn.parameters.size(); ++p )
            parameters += (p == 0 ? "" : ", ") + foreignParameterName(package, fn.parameters[p]);
        out += fmt("foreign function %%%zu \"%s\" (native \"%s\") (%s) -> %s\n",
                   i,
                   fn.name,
                   fn.cxx_name,
                   parameters,
                   typeName(package, fn.result_type));
    }

    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        auto function_id = FunctionId{static_cast<uint32_t>(i)};
        const auto& fn = package.function(function_id);

        // Only print a parameter list when there's one to show, so their exact
        // canonical dump is unaffected.
        std::string parameters;
        for ( size_t p = 0; p < fn.parameters.size(); ++p )
            parameters += (p == 0 ? "" : ", ") + typeName(package, fn.parameters[p]);

        // Only append the kind/parser-unit suffix for a `Parser` function, so
        // their exact canonical dump is unaffected.
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

        print_region(print_region, fn.root_region, "  ");
    }

    for ( const auto& root : package.parserRoots() )
        out += fmt("parser root: unit %%%u -> function %%%u\n", root.unit.index, root.function.index);

    for ( auto root : package.functionRoots() )
        out += fmt("function root: function %%%u\n", root.index);

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
