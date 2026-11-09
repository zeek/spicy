// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <unordered_set>
#include <variant>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/analyses/field-use.h>

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
