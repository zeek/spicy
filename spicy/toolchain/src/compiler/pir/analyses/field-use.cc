// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <optional>
#include <set>
#include <unordered_set>
#include <variant>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/analyses/field-use.h>
#include <spicy/compiler/detail/pir/ir/cfg.h>

using namespace spicy::detail::pir;
using namespace spicy::detail::pir::ir;

std::vector<Diagnostic> analyses::checkUnusedFields(const Package& package) {
    std::unordered_set<uint32_t> public_units;
    for ( const auto& root : package.parserRoots() )
        public_units.insert(root.unit.index);

    // Value IDs are unique across the package, so scan all functions together.
    std::unordered_set<uint32_t> used_fields;
    std::unordered_set<uint32_t> escaped_units;
    std::unordered_set<uint32_t> used_values;
    std::unordered_set<uint32_t> escaped_types;
    // Include units inside tuples and containers passed to foreign code.
    auto escape = [&](auto&& self, TypeId id) -> void {
        if ( ! escaped_types.insert(id.index).second )
            return;

        const auto& type = package.type(id);
        if ( type.kind == TypeKind::Unit )
            escaped_units.insert(type.declaration.index);
        for ( auto element : type.type_arguments )
            self(self, element);
    };

    for ( size_t i = 0; i < package.instructions().size(); ++i ) {
        InstId id{static_cast<uint32_t>(i)};
        const auto& inst = package.inst(id);

        if ( inst.opcode == Opcode::FieldPlace ) {
            if ( const auto* payload = std::get_if<FieldPayload>(&inst.payload) )
                used_fields.insert(payload->field.index);
        }

        for ( size_t a = 0; a < inst.args.size(); ++a ) {
            auto arg = inst.args[a];
            // Storing the parsed value in its field does not count as a use.
            if ( inst.opcode != Opcode::PublishField || a != 1 )
                used_values.insert(arg.index);

            // Foreign code may read any field.
            if ( inst.opcode == Opcode::OpaqueOp )
                escape(escape, package.inst(arg).result_type);
        }
    }

    // Find other uses of parsed values, such as `$$` in a field hook.
    for ( size_t i = 0; i < package.instructions().size(); ++i ) {
        const auto& inst = package.inst(InstId{static_cast<uint32_t>(i)});
        if ( inst.opcode != Opcode::PublishField || inst.args.size() < 2 )
            continue;

        const auto* payload = std::get_if<FieldPayload>(&inst.payload);
        if ( payload && used_values.contains(inst.args[1].index) )
            used_fields.insert(payload->field.index);
    }

    std::vector<Diagnostic> diags;
    DiagnosticEmitter emitter(package, diags);
    for ( size_t i = 0; i < package.typeDecls().size(); ++i ) {
        TypeDeclId unit_id{static_cast<uint32_t>(i)};
        const auto& unit = package.typeDecl(unit_id);
        if ( unit.kind != TypeDeclKind::Unit || public_units.contains(unit_id.index) ||
             escaped_units.contains(unit_id.index) )
            continue;

        for ( auto field : unit.fields ) {
            if ( ! used_fields.contains(field.index) )
                emitter.emit(diag::UnusedField,
                             field,
                             hilti::util::fmt("%s::%s", unit.name, package.declaration(field).name));
        }
    }

    return diags;
}

namespace {

// Fields set on every path to this point, indexed by `DeclId`.
using FieldSet = std::set<uint32_t>;

FieldSet intersect(const FieldSet& a, const FieldSet& b) {
    FieldSet out;
    std::ranges::set_intersection(a, b, std::inserter(out, out.begin()));
    return out;
}

// Tracks fields of `self` through a parser and its direct hook calls.
// Other calls may write any unit or field passed to them.
class ReadChecker {
public:
    ReadChecker(const Package& package, std::vector<Diagnostic>& diags) : _package(package), _emitter(package, diags) {}

    // The parser creates `self` with all fields unset.
    void checkParser(FunctionId function) {
        Selves selves;
        for ( auto block : _package.region(_package.function(function).root_region).blocks )
            for ( auto id : _package.block(block).insts )
                if ( _package.inst(id).opcode == Opcode::UnitCreate )
                    selves.insert(id.index);

        _flow(function, selves, {}, true);
    }

private:
    // IDs for `self`, including each `publish_field` result.
    using Selves = std::unordered_set<uint32_t>;

    // Returns the field if `place` addresses a field of `self`.
    std::optional<DeclId> _selfField(InstId place, const Selves& selves) const {
        const auto& inst = _package.inst(place);
        if ( inst.opcode != Opcode::FieldPlace || inst.args.empty() || ! selves.contains(inst.args[0].index) )
            return std::nullopt;

        return std::get<FieldPayload>(inst.payload).field;
    }

    FieldSet _allFields(InstId self) const {
        FieldSet out;
        const auto& type = _package.type(_package.inst(self).result_type);
        for ( auto field : _package.typeDecl(type.declaration).fields )
            out.insert(field.index);
        return out;
    }

    // Checks a hook whose parameter `index` is `self`. Returns fields set on every return path.
    FieldSet _hook(FunctionId hook, size_t index, const FieldSet& entry, bool report) {
        Selves selves;
        for ( auto block : _package.region(_package.function(hook).root_region).blocks )
            for ( auto id : _package.block(block).insts ) {
                const auto& inst = _package.inst(id);
                if ( inst.opcode == Opcode::Argument && std::get<ArgumentPayload>(inst.payload).index == index )
                    selves.insert(id.index);
            }

        return _flow(hook, selves, entry, report);
    }

    // Updates `set` for the block and optionally reports reads of unset fields.
    void _block(const Function& function, BlockId block, Selves& selves, FieldSet& set, bool report) {
        for ( auto id : _package.block(block).insts ) {
            const auto& inst = _package.inst(id);
            switch ( inst.opcode ) {
                case Opcode::PublishField:
                    if ( selves.contains(inst.args[0].index) ) {
                        set.insert(std::get<FieldPayload>(inst.payload).field.index);
                        selves.insert(id.index);
                    }
                    break;

                case Opcode::Load:
                    if ( auto field = _selfField(inst.args[0], selves);
                         field && ! set.contains(field->index) && report )
                        _report(id, *field);
                    break;

                case Opcode::Store:
                    if ( auto field = _selfField(inst.args[0], selves) )
                        set.insert(field->index);
                    break;

                case Opcode::Call:
                case Opcode::OpaqueOp:
                    for ( size_t a = 0; a < inst.args.size(); ++a ) {
                        auto arg = inst.args[a];
                        if ( selves.contains(arg.index) ) {
                            if ( inst.opcode == Opcode::Call && function.kind == FunctionKind::Parser )
                                set = _hook(std::get<FunctionPayload>(inst.payload).function, a, set, report);
                            else
                                set = _allFields(arg);
                        }
                        // Assume the callee writes any field passed by place.
                        else if ( auto field = _selfField(arg, selves) )
                            set.insert(field->index);
                    }
                    break;

                default: break;
            }
        }
    }

    // Finds fields set on every return path. Reports reads after block states stop changing.
    FieldSet _flow(FunctionId id, Selves selves, const FieldSet& entry, bool report) {
        const auto& function = _package.function(id);
        auto cfg = buildCfg(_package, function.root_region);
        if ( cfg.blocks.empty() )
            return entry;

        // No state means unreachable. Field sets only shrink as paths merge.
        std::vector<std::optional<FieldSet>> in(cfg.blocks.size());
        std::vector<std::optional<FieldSet>> out(cfg.blocks.size());
        in[0] = entry;
        std::vector<size_t> worklist = {0};
        while ( ! worklist.empty() ) {
            auto pos = worklist.back();
            worklist.pop_back();
            auto set = *in[pos];
            _block(function, cfg.blocks[pos], selves, set, false);
            if ( out[pos] == set )
                continue;

            out[pos] = set;
            for ( auto next : cfg.successors[pos] ) {
                auto merged = in[next] ? intersect(*in[next], set) : set;
                if ( in[next] != merged || ! out[next] ) {
                    in[next] = std::move(merged);
                    worklist.push_back(next);
                }
            }
        }

        std::optional<FieldSet> exit;
        for ( size_t pos = 0; pos < cfg.blocks.size(); ++pos ) {
            if ( ! in[pos] )
                continue; // unreachable

            auto set = *in[pos];
            _block(function, cfg.blocks[pos], selves, set, report);
            const auto& insts = _package.block(cfg.blocks[pos]).insts;
            if ( ! insts.empty() && _package.inst(insts.back()).opcode == Opcode::Return )
                exit = exit ? intersect(*exit, set) : set;
        }

        // No return means no new writes visible to the caller.
        return exit ? *exit : entry;
    }

    void _report(InstId read, DeclId field) {
        const auto& decl = _package.declaration(field);
        auto name = hilti::util::fmt("%s::%s", _package.typeDecl(decl.owner).name, decl.name);
        _emitter.emit(diag::FieldReadBeforeParsed, read, name).note(diag::FieldParsedHere, field, decl.name);
    }

    const Package& _package;
    DiagnosticEmitter _emitter;
};

} // namespace

std::vector<Diagnostic> analyses::checkFieldReads(const Package& package) {
    std::vector<Diagnostic> diags;
    ReadChecker checker(package, diags);
    for ( size_t i = 0; i < package.functions().size(); ++i ) {
        FunctionId id{static_cast<uint32_t>(i)};
        if ( package.function(id).kind == FunctionKind::Parser )
            checker.checkParser(id);
    }

    return diags;
}
