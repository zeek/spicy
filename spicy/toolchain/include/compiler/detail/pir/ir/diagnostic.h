// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <variant>
#include <vector>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/ir/diagnostic-definition.h>
#include <spicy/compiler/detail/pir/ir/diagnostics/core.h>
#include <spicy/compiler/detail/pir/ir/diagnostics/declarations.h>
#include <spicy/compiler/detail/pir/ir/diagnostics/parser.h>
#include <spicy/compiler/detail/pir/ir/diagnostics/source.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/source.h>

namespace spicy::detail::pir::ir {

/** A typed anchor for a diagnostic; `std::monostate` means no typed entity is available. */
using DiagnosticEntity =
    std::variant<std::monostate, FunctionId, RegionId, BlockId, InstId, TypeId, TypeDeclId, DeclId>;

/** Where a diagnostic (or note) points: an optional source span plus an optional typed IR anchor. */
struct DiagnosticSite {
    SourceSpanId source; /**< invalid means absent */
    DiagnosticEntity entity;
};

/** An explicit "nowhere" site, for diagnostics about the package as a whole. */
inline DiagnosticSite noSite() { return DiagnosticSite{}; }

struct DiagnosticNote {
    DiagnosticDefinition definition;
    std::string message; /**< formatted through `definition.message` */
    DiagnosticSite site;
};

/** A diagnostic carries the exact catalog definition it was raised from, not a re-derived copy. */
struct Diagnostic {
    DiagnosticDefinition definition;
    std::string message; /**< formatted through `definition.message` */
    DiagnosticSite primary;
    std::vector<DiagnosticNote> notes;
};

namespace detail {

// Overloaded on the anchor type so `emit()`/`note()` can accept a typed entity directly and
// have the emitter derive its site (and, for `FunctionId`/`InstId`, its stored source span)
// automatically. `Package` lookups happen here rather than at call sites.
inline DiagnosticSite siteFor(const Package& package, FunctionId id) {
    SourceSpanId span;
    if ( package.isValid(id) )
        span = package.function(id).span;
    return DiagnosticSite{.source = span, .entity = id};
}

inline DiagnosticSite siteFor(const Package& package, InstId id) {
    SourceSpanId span;
    if ( package.isValid(id) )
        span = package.inst(id).span;
    return DiagnosticSite{.source = span, .entity = id};
}

inline DiagnosticSite siteFor(const Package& /* package */, RegionId id) { return DiagnosticSite{.entity = id}; }

inline DiagnosticSite siteFor(const Package& /* package */, BlockId id) { return DiagnosticSite{.entity = id}; }

inline DiagnosticSite siteFor(const Package& /* package */, TypeId id) { return DiagnosticSite{.entity = id}; }

inline DiagnosticSite siteFor(const Package& package, TypeDeclId id) {
    SourceSpanId span;
    if ( package.isValid(id) )
        span = package.typeDecl(id).span;
    return DiagnosticSite{.source = span, .entity = id};
}

inline DiagnosticSite siteFor(const Package& package, DeclId id) {
    SourceSpanId span;
    if ( package.isValid(id) )
        span = package.declaration(id).span;
    return DiagnosticSite{.source = span, .entity = id};
}

inline DiagnosticSite siteFor(const Package& /* package */, SourceSpanId span) {
    return DiagnosticSite{.source = span};
}

inline DiagnosticSite siteFor(const Package& /* package */, DiagnosticSite site) { return site; }

} // namespace detail

/** Appends notes to the diagnostic most recently emitted through the owning `DiagnosticEmitter`. */
class DiagnosticBuilder {
public:
    DiagnosticBuilder(const Package& package, std::vector<Diagnostic>& sink, size_t index)
        : _package(package), _sink(sink), _index(index) {}

    /** Adds a "note" in order to add extra information to the diagnostic. */
    template<typename Anchor, typename... Args>
    DiagnosticBuilder& note(const DiagnosticDefinition& def, const Anchor& anchor, const Args&... args) {
        _sink[_index].notes.push_back(DiagnosticNote{
            .definition = def,
            .message = hilti::util::fmt(def.message, args...),
            .site = detail::siteFor(_package, anchor),
        });
        return *this;
    }

private:
    const Package& _package;
    std::vector<Diagnostic>& _sink;
    size_t _index;
};

/** Emits diagnostics. Holds a pre-created list of diagnostics as its sink. */
class DiagnosticEmitter {
public:
    DiagnosticEmitter(const Package& package, std::vector<Diagnostic>& sink) : _package(package), _sink(sink) {}

    /**
     * Emits the diagnostic. Potential anchors are the various siteFor
     * definitions. Use the Arena ID rather than the span directly.
     *
     * The returned value is a builder so that notes can be added.
     */
    template<typename Anchor, typename... Args>
    DiagnosticBuilder emit(const DiagnosticDefinition& def, const Anchor& anchor, const Args&... args) {
        _sink.push_back(Diagnostic{
            .definition = def,
            .message = hilti::util::fmt(def.message, args...),
            .primary = detail::siteFor(_package, anchor),
            .notes = {},
        });
        return DiagnosticBuilder(_package, _sink, _sink.size() - 1);
    }

private:
    const Package& _package;
    std::vector<Diagnostic>& _sink;
};

/** Renders diagnostics deterministically; tolerant of malformed source/entity references. */
std::string render(const Package& package, const std::vector<Diagnostic>& diagnostics);

} // namespace spicy::detail::pir::ir
