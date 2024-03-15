// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/forward.h>
#include <hilti/ast/id.h>
#include <hilti/base/util.h>

namespace hilti::printer {

class Stream;

/**
 * Prints an AST as HILTI source code. This consults any installed plugin
 * `print_ast` hooks.
 */
void print(std::ostream& out, Node* root, bool compact = false);

/**
 * Prints an AST as HILTI source code. This consults any installed plugin
 * `print_ast` hooks.
 */
void print(Stream& stream, Node* root); // NOLINT

namespace detail {

/** Maintains printer state while output is in progress. */
struct State {
    std::vector<ID> scopes = {""};
    std::string pending;
    int indent = 0;
    bool wrote_nl = false;
    bool first_in_block = false;
    bool last_in_block = false;
    bool expand_subsequent_type = false;
    bool compact = false;

    inline static std::unique_ptr<State> current;
    inline static uint64_t depth = 0;
};
} // namespace detail

/** Output stream formatting HILTI source code. */
class Stream {
public:
    Stream(std::ostream& s) : _stream(s) {}

    auto& state() const {
        assert(detail::State::current);
        return *detail::State::current;
    }

    void beginLine() {
        _flush_pending();
        _stream << std::string(static_cast<size_t>(state().indent) * 4, ' ');
    }

    void endLine() { _stream << '\n'; }

    void emptyLine() {
        if ( state().wrote_nl )
            return;

        endLine();
        state().wrote_nl = true;
    }

    char newline() const { return '\n'; }

    bool isExpandSubsequentType() const { return state().expand_subsequent_type; }
    void setExpandSubsequentType(bool expand) { state().expand_subsequent_type = expand; }

    bool isCompact() const { return state().compact; }
    void setCompact(bool compact) { state().compact = compact; }


    bool isFirstInBlock() const { return state().first_in_block; }
    bool isLastInBlock() const { return state().last_in_block; }
    void setPositionInBlock(bool first, bool last) {
        state().first_in_block = first;
        state().last_in_block = last;
    }

    auto indent() const { return state().indent; }
    void incrementIndent() { ++state().indent; }
    void decrementIndent() {
        --state().indent;
        state().first_in_block = state().last_in_block = false;
    }

    const ID& currentScope() { return state().scopes.back(); }
    void pushScope(ID id) { state().scopes.push_back(std::move(id)); }
    void popScope() { state().scopes.pop_back(); }

    template<typename T, IF_DERIVED_FROM(T, Node)>
    Stream& operator<<(T* t) {
        _flush_pending();
        ::hilti::printer::print(*this, t);
        return *this;
    }

    Stream& operator<<(const ID& id);

    template<typename T, IF_NOT_DERIVED_FROM(T, Node)>
    Stream& operator<<(const T& t) {
        state().wrote_nl = false;
        _flush_pending();
        _stream << t;
        return *this;
    }

    // Output lists.
    template<typename T>
    Stream& operator<<(std::pair<T, const char*> p) {
        bool first = true;
        for ( const auto& i : p.first ) {
            _flush_pending();

            if ( ! first )
                _stream << p.second;

            (*this) << i;
            first = false;
        }

        return *this;
    }

    template<typename T>
    Stream& operator<<(std::pair<T*, const char*> p) {
        bool first = true;
        for ( auto& i : p.first ) {
            _flush_pending();

            if ( ! first )
                _stream << p.second;

            (*this) << *i;
            first = false;
        }

        return *this;
    }

private:
    void _flush_pending() {
        _stream << state().pending;
        state().pending.clear();
    }

    std::ostream& _stream;
};

} // namespace hilti::printer
