// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <unordered_set>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/backends/hilti/coverage.h>

using ::hilti::util::fmt;

namespace spicy::detail::pir::backend::hilti {

namespace {

::hilti::Location toLocation(const ir::Package& package, ir::SourceSpanId id) {
    if ( ! package.sourceManager().isValid(id) )
        return {};
    const auto& span = package.sourceManager().span(id);
    const auto& file = package.sourceManager().file(span.file);
    return ::hilti::Location(file.diagnostic_path, span.begin_line, span.end_line, span.begin_column, span.end_column);
}

void report(std::vector<UnsupportedFeature>& out, std::string feature, std::string reason, ::hilti::Location loc = {}) {
    out.push_back({.feature = std::move(feature), .reason = std::move(reason), .location = std::move(loc)});
}

// Whether the HILTI backend can materialize a value of this type as a unit field or vector element.
bool isStorageType(const ir::Package& package, ir::TypeId id) {
    const auto& type = package.type(id);
    switch ( type.kind ) {
        case ir::TypeKind::UInt8:
        case ir::TypeKind::UInt64:
        case ir::TypeKind::Bytes:
        case ir::TypeKind::Unit: return true;
        case ir::TypeKind::Vector: return isStorageType(package, type.type_arguments[0]);
        case ir::TypeKind::Void:
        case ir::TypeKind::Int64:
        case ir::TypeKind::ParserState:
        case ir::TypeKind::Opaque:
        case ir::TypeKind::Place:
        case ir::TypeKind::Bool:
        case ir::TypeKind::String:
        case ir::TypeKind::Tuple: return false;
    }
    return false;
}

void checkRegion(const ir::Package& package,
                 ir::RegionId region,
                 std::vector<UnsupportedFeature>& out,
                 unsigned bound_depth) {
    for ( auto block_id : package.region(region).blocks ) {
        for ( auto id : package.block(block_id).insts ) {
            const auto& inst = package.inst(id);
            const auto* schema = ir::schemaFor(inst.opcode);
            auto unsupported = [&](std::string reason) {
                report(out,
                       schema ? std::string(schema->spelling) : "instruction",
                       std::move(reason),
                       toLocation(package, inst.span));
            };
            if ( inst.opcode == ir::Opcode::EnterBound ) {
                if ( bound_depth != 0 )
                    unsupported("nested byte bounds are not supported by the HILTI consumer");
                ++bound_depth;
            }
            else if ( inst.opcode == ir::Opcode::LeaveBound && bound_depth != 0 )
                --bound_depth;
            switch ( inst.opcode ) {
                case ir::Opcode::Argument:
                case ir::Opcode::RegionArgument:
                case ir::Opcode::TupleGet:
                case ir::Opcode::UnitCreate:
                case ir::Opcode::PublishField:
                case ir::Opcode::Finish:
                case ir::Opcode::Yield:
                case ir::Opcode::VectorEmpty:
                case ir::Opcode::VectorAppend:
                case ir::Opcode::EnterBound:
                case ir::Opcode::LeaveBound:
                case ir::Opcode::RepeatToBound:
                    for ( size_t i = 1; i < inst.args.size(); ++i ) {
                        if ( ! isStorageType(package, package.inst(inst.args[i]).result_type) )
                            unsupported("carried values must be storage types the HILTI backend can represent");
                    }
                    break;
                case ir::Opcode::ParseSubunit:
                case ir::Opcode::ReadBytes: break;
                case ir::Opcode::ReadInteger: {
                    const auto* p = std::get_if<ir::ReadIntegerPayload>(&inst.payload);
                    if ( ! p || (p->width != 8 && p->width != 64) || p->signedness != ir::Signedness::Unsigned ||
                         p->byte_order != ir::ByteOrder::Network )
                        unsupported("only unsigned width-8 and width-64 network-order reads are supported");
                    break;
                }
                // Byte bounds may compute their length from calls, constants, and fields, so those operations are
                // lowered in parser functions too.
                case ir::Opcode::Constant:
                case ir::Opcode::Add:
                case ir::Opcode::Call:
                case ir::Opcode::OpaqueOp:
                case ir::Opcode::FieldPlace:
                case ir::Opcode::Load: break;
                case ir::Opcode::Return:
                case ir::Opcode::LocalPlace:
                case ir::Opcode::Store:
                case ir::Opcode::Tuple:
                case ir::Opcode::BoolConstant:
                case ir::Opcode::StringConstant:
                case ir::Opcode::BytesConstant: unsupported("procedural lowering is not supported"); break;
            }
            for ( auto child : inst.regions )
                checkRegion(package, child, out, bound_depth);
        }
    }
}

} // namespace

namespace {

// Whether the HILTI backend can lower a value of this type in an ordinary function or foreign signature.
bool isProcedureType(const ir::Package& package, ir::TypeId id) {
    const auto& type = package.type(id);
    switch ( type.kind ) {
        case ir::TypeKind::Void:
        case ir::TypeKind::Int64:
        case ir::TypeKind::UInt8:
        case ir::TypeKind::UInt64:
        case ir::TypeKind::Bytes:
        case ir::TypeKind::Bool:
        case ir::TypeKind::String: return true;
        case ir::TypeKind::Place: return isProcedureType(package, type.type_arguments[0]);
        case ir::TypeKind::Tuple:
            return std::ranges::all_of(type.type_arguments,
                                       [&](ir::TypeId element) { return isProcedureType(package, element); });
        case ir::TypeKind::Opaque: {
            const auto& decl = package.typeDecl(type.declaration);
            return decl.opaque && decl.opaque->lifecycle && ! decl.opaque->cxx_name.empty();
        }
        case ir::TypeKind::ParserState:
        case ir::TypeKind::Unit:
        case ir::TypeKind::Vector: return false;
    }
    return false;
}

// Ordinary functions have no structured regions, so their body is a flat list of procedural operations.
void checkProcedureRegion(const ir::Package& package, ir::RegionId region, std::vector<UnsupportedFeature>& out) {
    for ( auto block_id : package.region(region).blocks ) {
        for ( auto id : package.block(block_id).insts ) {
            const auto& inst = package.inst(id);
            const auto* schema = ir::schemaFor(inst.opcode);
            auto unsupported = [&](std::string reason) {
                report(out,
                       schema ? std::string(schema->spelling) : "instruction",
                       std::move(reason),
                       toLocation(package, inst.span));
            };
            switch ( inst.opcode ) {
                case ir::Opcode::Argument:
                case ir::Opcode::Constant:
                case ir::Opcode::Add:
                case ir::Opcode::Return:
                case ir::Opcode::Call:
                case ir::Opcode::OpaqueOp:
                case ir::Opcode::LocalPlace:
                case ir::Opcode::Load:
                case ir::Opcode::Store:
                case ir::Opcode::Tuple:
                case ir::Opcode::BoolConstant:
                case ir::Opcode::StringConstant:
                case ir::Opcode::BytesConstant: break;
                default: unsupported("not a procedural operation the HILTI backend can lower"); break;
            }

            if ( package.isValid(inst.result_type) && ! isProcedureType(package, inst.result_type) )
                unsupported("value type is not supported by the HILTI backend yet");
        }
    }
}

} // namespace

std::vector<UnsupportedFeature> checkCoverage(const ir::Package& package) {
    std::vector<UnsupportedFeature> out;
    if ( package.parserRoots().empty() && package.functionRoots().empty() )
        report(out, "package", "no parser or function root");

    for ( size_t i = 0; i < package.types().size(); ++i ) {
        const auto& type = package.type(ir::TypeId{static_cast<uint32_t>(i)});
        switch ( type.kind ) {
            case ir::TypeKind::Void:
            case ir::TypeKind::Int64:
            case ir::TypeKind::UInt8:
            case ir::TypeKind::UInt64:
            case ir::TypeKind::Bytes:
            case ir::TypeKind::ParserState:
            case ir::TypeKind::Unit:
            case ir::TypeKind::Place:
            case ir::TypeKind::Bool:
            case ir::TypeKind::String:
            case ir::TypeKind::Tuple:
            case ir::TypeKind::Opaque: break;
            case ir::TypeKind::Vector:
                if ( ! isStorageType(package, type.type_arguments[0]) )
                    report(out, "vector", "vector element type cannot be stored by the HILTI backend");
                break;
        }
    }

    for ( size_t i = 0; i < package.foreignFunctions().size(); ++i ) {
        const auto& fn = package.foreignFunction(ir::ForeignFunctionId{static_cast<uint32_t>(i)});
        bool representable = isProcedureType(package, fn.result_type);
        for ( const auto& parameter : fn.parameters )
            representable = representable && (parameter.argument != ir::ForeignArgument::Value ||
                                              isProcedureType(package, parameter.type));
        if ( ! representable )
            report(out,
                   "foreign function",
                   fmt("foreign function '%s' has a signature the HILTI backend cannot call yet", fn.name),
                   toLocation(package, fn.span));
    }

    for ( size_t i = 0; i < package.declarations().size(); ++i ) {
        const auto& field = package.declaration(ir::DeclId{static_cast<uint32_t>(i)});
        if ( ! isStorageType(package, field.type) )
            report(out,
                   "field",
                   fmt("field '%s' cannot be stored by the HILTI backend", field.name),
                   toLocation(package, field.span));
    }

    std::unordered_set<uint32_t> reached;
    std::unordered_set<uint32_t> active;
    std::unordered_set<uint32_t> root_functions;
    for ( const auto& root : package.parserRoots() )
        root_functions.insert(root.function.index);
    auto walk = [&](auto&& self, ir::FunctionId id) -> void {
        if ( active.contains(id.index) ) {
            report(out, "function", "recursive call is not supported");
            return;
        }
        if ( ! reached.insert(id.index).second )
            return;
        active.insert(id.index);
        const auto& function = package.function(id);
        if ( function.kind == ir::FunctionKind::Parser )
            checkRegion(package, function.root_region, out, root_functions.contains(id.index) ? 0 : 1);
        else
            checkProcedureRegion(package, function.root_region, out);
        auto walk_calls = [&](auto&& region_walk, ir::RegionId region) -> void {
            for ( auto block : package.region(region).blocks )
                for ( auto inst_id : package.block(block).insts ) {
                    const auto& inst = package.inst(inst_id);
                    if ( const auto* p = std::get_if<ir::FunctionPayload>(&inst.payload) ) {
                        if ( inst.opcode == ir::Opcode::ParseSubunit && root_functions.contains(p->function.index) )
                            report(out, "parser.parse_subunit", "child call targets a public parser root");
                        self(self, p->function);
                    }
                    for ( auto child : inst.regions )
                        region_walk(region_walk, child);
                }
        };
        walk_calls(walk_calls, function.root_region);
        active.erase(id.index);
    };
    for ( const auto& root : package.parserRoots() )
        walk(walk, root.function);
    for ( auto root : package.functionRoots() )
        walk(walk, root);
    if ( ! (package.parserRoots().empty() && package.functionRoots().empty()) &&
         reached.size() != package.functions().size() )
        report(out, "package", "contains a function unreachable from roots");
    return out;
}

} // namespace spicy::detail::pir::backend::hilti
