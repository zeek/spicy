// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <array>
#include <unordered_set>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/backends/hilti/coverage.h>

using ::hilti::util::fmt;

namespace spicy::detail::pir::backend::hilti {

namespace {

using ir::Opcode;

::hilti::Location toLocation(const ir::Package& package, ir::SourceSpanId id) {
    if ( ! package.sourceManager().isValid(id) )
        return {};

    const auto& span = package.sourceManager().span(id);
    std::string file;
    if ( package.sourceManager().isValid(span.file) )
        file = package.sourceManager().file(span.file).diagnostic_path;

    return ::hilti::Location(file, span.begin_line, span.end_line, span.begin_column, span.end_column);
}

/** The exact single-block instruction sequence this backend accepts, in order. */
constexpr std::array<Opcode, 7> AcceptedBlockShape = {
    Opcode::Argument,
    Opcode::UnitCreate,
    Opcode::ReadInteger,
    Opcode::TupleGet,
    Opcode::TupleGet,
    Opcode::PublishField,
    Opcode::Finish,
};

/** Checks one parser root's unit, function, and single block. */
class RootChecker {
public:
    RootChecker(const ir::Package& package, const ir::ParserRoot& root, std::vector<UnsupportedFeature>& out)
        : _package(package), _root(root), _out(out) {}

    void run() {
        _checkUnit();
        _checkFunction();
    }

private:
    void _report(std::string_view feature, std::string reason, ::hilti::Location loc = {}) {
        _out.push_back(UnsupportedFeature{
            .feature = std::string(feature),
            .reason = std::move(reason),
            .location = std::move(loc),
        });
    }

    void _checkUnit() {
        const auto& unit = _package.typeDecl(_root.unit);
        if ( unit.fields.size() != 1 ) {
            _report("unit",
                    fmt("unit '%s' must have exactly one field for this backend, has %d",
                        unit.name,
                        unit.fields.size()),
                    toLocation(_package, unit.span));
            return;
        }

        const auto& field = _package.declaration(unit.fields[0]);
        if ( _package.type(field.type).kind != ir::TypeKind::UInt8 )
            _report("unit field",
                    fmt("field '%s' must be uint8 for this backend", field.name),
                    toLocation(_package, field.span));
    }

    void _checkFunction() {
        const auto& fn = _package.function(_root.function);
        if ( fn.kind != ir::FunctionKind::Parser ) {
            _report("function", fmt("function '%s' is not a parser function", fn.name), toLocation(_package, fn.span));
            return;
        }

        const auto& region = _package.region(fn.root_region);
        if ( region.blocks.size() != 1 ) {
            _report("function",
                    fmt("function '%s' must have exactly one block for this backend, has %d",
                        fn.name,
                        region.blocks.size()),
                    toLocation(_package, fn.span));
            return;
        }

        const auto& block = _package.block(region.blocks[0]);
        if ( block.insts.size() != AcceptedBlockShape.size() ) {
            _report("function",
                    fmt("function '%s' must have exactly the accepted one-byte-parser instruction "
                        "sequence, found %d instruction(s)",
                        fn.name,
                        block.insts.size()),
                    toLocation(_package, fn.span));
            return;
        }

        for ( size_t i = 0; i < AcceptedBlockShape.size(); ++i ) {
            const auto& inst = _package.inst(block.insts[i]);
            if ( inst.opcode != AcceptedBlockShape[i] ) {
                const auto* schema = ir::schemaFor(inst.opcode);
                _report("instruction",
                        fmt("instruction %d of function '%s' must be '%s' for this backend, found '%s'",
                            i,
                            fn.name,
                            ir::schemaFor(AcceptedBlockShape[i])->spelling,
                            schema ? schema->spelling : "<unknown>"),
                        toLocation(_package, inst.span));
                return;
            }
        }

        _checkReadInteger(block.insts[2]);
    }

    void _checkReadInteger(ir::InstId id) {
        const auto& inst = _package.inst(id);
        const auto* payload = std::get_if<ir::ReadIntegerPayload>(&inst.payload);
        if ( ! payload ) {
            _report("parser.read_integer", "malformed read-integer payload", toLocation(_package, inst.span));
            return;
        }

        if ( payload->width != 8 || payload->signedness != ir::Signedness::Unsigned ||
             payload->byte_order != ir::ByteOrder::Network )
            _report("parser.read_integer",
                    fmt("only unsigned width-8 network-byte-order reads are supported, found width=%d signed=%s "
                        "byte_order=%d",
                        payload->width,
                        payload->signedness == ir::Signedness::Signed ? "true" : "false",
                        static_cast<int>(payload->byte_order)),
                    toLocation(_package, inst.span));
    }

    const ir::Package& _package;
    const ir::ParserRoot& _root;
    std::vector<UnsupportedFeature>& _out;
};

/** Whether every package type is among the closed set this backend can represent. */
void checkTypes(const ir::Package& package, std::vector<UnsupportedFeature>& out) {
    std::unordered_set<uint32_t> root_units;
    for ( const auto& root : package.parserRoots() )
        root_units.insert(root.unit.index);

    for ( size_t i = 0; i < package.types().size(); ++i ) {
        ir::TypeId id{static_cast<uint32_t>(i)};
        const auto& type = package.type(id);

        switch ( type.kind ) {
            case ir::TypeKind::Void:
            case ir::TypeKind::Int64:
            case ir::TypeKind::UInt8:
            case ir::TypeKind::ParserState: continue;

            case ir::TypeKind::Unit:
                if ( root_units.contains(type.declaration.index) )
                    continue;
                out.push_back(UnsupportedFeature{
                    .feature = "type",
                    .reason =
                        fmt("unit type '%s' is not a parser root's unit", package.typeDecl(type.declaration).name),
                });
                continue;

            case ir::TypeKind::Tuple:
                if ( type.type_arguments.size() == 2 &&
                     package.type(type.type_arguments[0]).kind == ir::TypeKind::ParserState &&
                     package.type(type.type_arguments[1]).kind == ir::TypeKind::UInt8 )
                    continue;
                out.push_back(
                    UnsupportedFeature{.feature = "type", .reason = "only tuple<parser.state, uint8> is supported"});
                continue;
        }
    }
}

} // namespace

std::vector<UnsupportedFeature> checkCoverage(const ir::Package& package) {
    std::vector<UnsupportedFeature> result;

    if ( package.parserRoots().empty() ) {
        result.push_back(UnsupportedFeature{.feature = "package", .reason = "no parser root"});
        return result;
    }

    // No procedural code allowed yet.
    if ( package.functions().size() != package.parserRoots().size() ) {
        result.push_back(UnsupportedFeature{
            .feature = "package",
            .reason = "contains a function outside a parser root; procedural PIR-to-HILTI "
                      "lowering is not supported by this backend",
        });
        return result;
    }

    for ( const auto& root : package.parserRoots() )
        RootChecker(package, root, result).run();

    checkTypes(package, result);

    return result;
}

} // namespace spicy::detail::pir::backend::hilti
