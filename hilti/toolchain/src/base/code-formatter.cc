// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/base/code-formatter.h>
#include <hilti/base/logger.h>

using namespace hilti;
using namespace hilti::code_formatter;

void CodeFormatter::next() {
    // _out << "| " << _at_bol << "/" << _indent << " ";
    if ( _at_bol ) {
        _out << std::string(static_cast<std::string::size_type>(_indent * 4), ' ');
        _at_bol = false;
    }
}

void CodeFormatter::separator() {
    if ( _did_sep )
        return;

    _out << '\n';
    _at_bol = true;
    _did_sep = true;
    _in_comment = false;
}

void CodeFormatter::eol() {
    _out << '\n';
    _did_sep = false;
    _at_bol = true;
    _in_comment = false;
}

void CodeFormatter::eos() {
    next();
    _out << ';';
    eol();
}

void CodeFormatter::quoted(const std::string& s) {
    next();
    _out << '"' << util::escapeUTF8(s) << '"';
}

void CodeFormatter::comment(const std::string& s) {
    if ( ! _in_comment )
        separator();

    next();
    _out << _comment << ' ' << s;
    eol();
    _in_comment = true;
}

CodeFormatter& CodeFormatter::printString(const std::string& s) {
    std::string::size_type i = 0;

    while ( i < s.size() ) {
        auto j = s.find('\n', i);

        if ( j == std::string::npos )
            break;

        if ( j != i ) {
            next();
            _out << s.substr(i, j - i);
        }

        eol();
        i = j + 1;
    }

    if ( i != std::string::npos ) {
        next();
        _out << s.substr(i);
    }

    return *this;
}
