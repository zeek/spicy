// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/util.h>

#include <hilti/base/preprocessor.h>
#include <hilti/base/util.h>

using namespace hilti::util;

hilti::Result<hilti::util::SourceCodePreprocessor::State> hilti::util::SourceCodePreprocessor::processLine(
    std::string_view directive, std::string_view expression) {
    if ( directive == "@if" ) {
        if ( state() == State::Include ) {
            auto result = _parseIf(expression);
            if ( ! result )
                return result.error();

            _stack.push_back(*result ? 1 : 0);
        }
        else
            _stack.push_back(-1);
    }

    else if ( directive == "@else" ) {
        if ( expression.size() )
            return result::Error("syntax error in @else directive");

        if ( _stack.size() == 1 )
            return result::Error("@else without @if");

        if ( auto x = _stack.back(); x >= 0 ) {
            _stack.pop_back();
            _stack.push_back(1 - x);
        }
    }

    else if ( directive == "@endif" ) {
        if ( expression.size() )
            return result::Error("syntax error in @else directive");

        if ( _stack.size() == 1 )
            return result::Error("@endif without @if");

        _stack.pop_back();
    }

    else
        return result::Error("unknown preprocessor directive");

    return state();
}


hilti::Result<bool> hilti::util::SourceCodePreprocessor::_parseIf(const std::string_view& expression) {
    bool negate = false;

    auto m = hilti::rt::split(expression);

    if ( m.size() >= 1 && m[0] == "!" ) {
        negate = true;
        m = toVector(util::slice(m, 1)); // "shift m"
    }

    if ( m.size() != 1 && m.size() != 3 )
        return result::Error("syntax error in @if directive");

    auto id = std::string(m[0]);

    std::string op;
    int want = 0;

    if ( m.size() == 3 ) {
        // "<id> <operator> <expr>"
        op = std::string(m[1]);
        want = 0;

        if ( const auto* x = hilti::rt::atoi_n(m[2].begin(), m[2].end(), 10, &want); x != m[2].end() )
            return result::Error("cannot parse integer value");
    }
    else {
        // "<id>" => "<id> != 0"
        op = "!=";
        want = 0;
    }

    int have = 0;

    if ( auto x = _constants.find(id); x != _constants.end() )
        have = x->second;

    bool result = false;

    if ( op == "==" )
        result = (have == want);
    else if ( op == "!=" )
        result = (have != want);
    else if ( op == "<" )
        result = (have < want);
    else if ( op == "<=" )
        result = (have <= want);
    else if ( op == ">" )
        result = (have > want);
    else if ( op == ">=" )
        result = (have >= want);
    else
        return result::Error("unknown operator in preprocessor expression");

    return negate ? ! result : result;
}
