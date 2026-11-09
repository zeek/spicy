// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/base/util.h>

#include <spicy/compiler/detail/pir/ir/diagnostic.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::ir {

/** A note attached to an internal compiler error. */
struct InternalNote {
    std::string tag;
    std::string message;
    DiagnosticSite site;
};

/**
 * An internal compiler error caused by malformed PIR. These errors cannot be suppressed.
 * `tag` identifies the failed check so tests need not match the message.
 */
struct InternalError {
    std::string tag;
    std::string message;
    DiagnosticSite site;
    std::vector<InternalNote> notes;
};

/** Adds notes to an emitted error. */
class InternalErrorBuilder {
public:
    InternalErrorBuilder(const Package& package, std::vector<InternalError>& sink, size_t index)
        : _package(package), _sink(sink), _index(index) {}

    /** Adds a note at `anchor`, using the same location lookup as `emit()`. */
    template<typename Anchor, typename... Args>
    InternalErrorBuilder& note(const char* tag, const char* message, const Anchor& anchor, const Args&... args) {
        _sink[_index].notes.push_back(InternalNote{
            .tag = tag,
            .message = hilti::util::fmt(message, args...),
            .site = detail::siteFor(_package, anchor),
        });
        return *this;
    }

private:
    const Package& _package;
    std::vector<InternalError>& _sink;
    size_t _index;
};

/** Appends internal errors to the supplied vector. */
class InternalErrorEmitter {
public:
    InternalErrorEmitter(const Package& package, std::vector<InternalError>& sink) : _package(package), _sink(sink) {}

    /**
     * Emits an error at `anchor`. Function and instruction anchors include their source spans.
     *
     * @param tag short kebab-case name for the failed check
     * @param message format string
     * @return a builder that adds notes to the error
     */
    template<typename Anchor, typename... Args>
    InternalErrorBuilder emit(const char* tag, const char* message, const Anchor& anchor, const Args&... args) {
        _sink.push_back(InternalError{
            .tag = tag,
            .message = hilti::util::fmt(message, args...),
            .site = detail::siteFor(_package, anchor),
            .notes = {},
        });
        return InternalErrorBuilder(_package, _sink, _sink.size() - 1);
    }

private:
    const Package& _package;
    std::vector<InternalError>& _sink;
};

/**
 * Renders errors in order, with the IR entity followed by its source location.
 * Handles invalid entity IDs and source spans.
 */
std::string render(const Package& package, const std::vector<InternalError>& errors);

} // namespace spicy::detail::pir::ir
