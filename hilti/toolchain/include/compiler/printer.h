// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include <hilti/base/util.h>
#include <hilti/compiler/detail/visitors.h>

namespace hilti::printer {

class Stream {
public:
    Stream(std::ostream& s, bool _compact) : _stream(s), _compact(_compact), _nl(_compact ? ' ' : '\n') {}

    void beginLine() {
        _flush_pending();
        _stream << std::string(static_cast<size_t>(_indent) * 4, ' ');
    }
    void endLine() {
        if ( _compact )
            _pending = ' ';
        else
            _stream << '\n';
    }

    void emptyLine() {
        if ( _wrote_nl )
            return;

        endLine();
        _wrote_nl = true;
    }

    char newline() const { return _nl; }

    bool isCompact() { return _compact; }
    bool setCompact(bool new_compact) {
        auto old = _compact;
        _compact = new_compact;
        return old;
    }

    bool isExpandSubsequentType() const { return _expand_subsequent_type; }
    void setExpandSubsequentType(bool expand) { _expand_subsequent_type = expand; }

    bool isFirstInBlock() const { return _first_in_block; }
    bool isLastInBlock() const { return _last_in_block; }
    void setPositionInBlock(bool first, bool last) {
        _first_in_block = first;
        _last_in_block = last;
    }

    auto indent() const { return _indent; }
    void incrementIndent() { ++_indent; }
    void decrementIndent() {
        --_indent;
        _first_in_block = _last_in_block = false;
    }

    template<typename T, IF_DERIVED_FROM(T, trait::isNode)>
    Stream& operator<<(const T& t) {
        _flush_pending();
        if constexpr ( std::is_base_of<trait::isType, T>::value ) {
            if ( auto id = Type(t).typeID() )
                _stream << *id;
        }
        else
            hilti::detail::printAST(t, *this);

        return *this;
    }

    template<typename T, IF_NOT_DERIVED_FROM(T, trait::isNode)>
    Stream& operator<<(const T& t) {
        _wrote_nl = false;
        _flush_pending();
        _stream << t;
        _expand_subsequent_type = false;
        return *this;
    }

    // Output lists.
    template<typename T>
    Stream& operator<<(std::pair<T, const char*> p) {
        bool first = true;
        for ( auto& i : p.first ) {
            _flush_pending();

            if ( ! first )
                _stream << p.second;

            (*this) << i;
            first = false;
        }

        return *this;
    }

private:
    void _flush_pending() {
        _stream << _pending;
        _pending.clear();
    }

    std::ostream& _stream;
    bool _compact;
    char _nl;
    std::string _pending;
    int _indent = 0;
    bool _wrote_nl = false;
    bool _first_in_block = false;
    bool _last_in_block = false;
    bool _expand_subsequent_type = false;
};

} // namespace hilti::printer
