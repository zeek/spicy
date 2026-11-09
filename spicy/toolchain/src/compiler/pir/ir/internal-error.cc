// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/ir/internal-error.h>
#include <spicy/compiler/detail/pir/ir/printer.h>

using hilti::util::fmt;

namespace spicy::detail::pir::ir {

namespace {

/** Absent when `span` itself is unset; otherwise always renders, even for a malformed reference. */
std::optional<std::string> renderLocation(const Package& package, SourceSpanId span) {
    if ( ! span.isSet() )
        return std::nullopt;

    const auto& sources = package.sourceManager();
    if ( ! sources.isValid(span) )
        return std::string("<invalid-span>");

    const auto& s = sources.span(span);
    if ( ! sources.isValid(s.file) )
        return std::string("<invalid-file>");

    const auto& path = sources.file(s.file).diagnostic_path;
    if ( s.begin_line < 0 )
        return path;

    if ( s.begin_column < 0 )
        return fmt("%s:%d", path, s.begin_line);

    return fmt("%s:%d:%d", path, s.begin_line, s.begin_column);
}

std::string renderEntity(const Package& package, const DiagnosticEntity& entity) {
    if ( const auto* id = std::get_if<FunctionId>(&entity) ) {
        if ( package.isValid(*id) ) {
            const auto& fn = package.function(*id);
            if ( ! fn.name.empty() )
                return fmt("function %%%u \"%s\"", id->index, fn.name);
            return fmt("function %%%u", id->index);
        }
        return fmt("function %%%u (invalid)", id->index);
    }

    if ( const auto* id = std::get_if<RegionId>(&entity) )
        return fmt("region %%%u", id->index);

    if ( const auto* id = std::get_if<BlockId>(&entity) )
        return fmt("block %%%u", id->index);

    if ( const auto* id = std::get_if<InstId>(&entity) ) {
        if ( package.isValid(*id) ) {
            const auto& inst = package.inst(*id);
            if ( const auto* schema = schemaFor(inst.opcode) )
                return fmt("instruction %%%u (%s)", id->index, schema->spelling);
        }
        return fmt("instruction %%%u", id->index);
    }

    if ( const auto* id = std::get_if<TypeId>(&entity) )
        return fmt("type %%%u \"%s\"", id->index, typeName(package, *id));

    if ( const auto* id = std::get_if<TypeDeclId>(&entity) ) {
        if ( package.isValid(*id) ) {
            const auto& decl = package.typeDecl(*id);
            const char* kind = decl.kind == TypeDeclKind::Opaque ? "opaque type" : "unit";
            if ( ! decl.name.empty() )
                return fmt("%s %%%u \"%s\"", kind, id->index, decl.name);
            return fmt("%s %%%u", kind, id->index);
        }
        return fmt("unit %%%u (invalid)", id->index);
    }

    if ( const auto* id = std::get_if<ForeignFunctionId>(&entity) ) {
        if ( package.isValid(*id) ) {
            const auto& fn = package.foreignFunction(*id);
            if ( ! fn.name.empty() )
                return fmt("foreign function %%%u \"%s\"", id->index, fn.name);
            return fmt("foreign function %%%u", id->index);
        }
        return fmt("foreign function %%%u (invalid)", id->index);
    }

    if ( const auto* id = std::get_if<DeclId>(&entity) ) {
        if ( package.isValid(*id) ) {
            const auto& field = package.declaration(*id);
            if ( ! field.name.empty() )
                return fmt("field %%%u \"%s\"", id->index, field.name);
            return fmt("field %%%u", id->index);
        }
        return fmt("field %%%u (invalid)", id->index);
    }

    return "";
}

void renderOne(std::string& out,
               const Package& package,
               std::string_view kind,
               const std::string& tag,
               const std::string& message,
               const DiagnosticSite& site) {
    out += fmt("internal compiler %s[%s]\n", kind, tag);

    if ( auto entity = renderEntity(package, site.entity); ! entity.empty() )
        out += fmt("  at %s\n", entity);

    if ( auto location = renderLocation(package, site.source) )
        out += fmt("  source origin: %s\n", *location);

    out += fmt("  detail: %s\n", message);
}

} // namespace

std::string render(const Package& package, const std::vector<InternalError>& errors) {
    std::string out;

    for ( const auto& e : errors ) {
        renderOne(out, package, "error", e.tag, e.message, e.site);

        for ( const auto& note : e.notes )
            renderOne(out, package, "note", note.tag, note.message, note.site);
    }

    return out;
}

} // namespace spicy::detail::pir::ir
