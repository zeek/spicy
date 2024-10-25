// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <tuple>

#include <hilti/ast/location.h>
#include <hilti/base/util.h>

using namespace hilti;

const Location location::None;

Location::operator bool() const { return _file != location::None._file; }

Location Location::merge(const Location& loc) const {
    if ( _file != loc._file )
        return *this;

    auto [from_line, from_character] =
        std::min(std::tie(_from_line, _from_character), std::tie(loc._from_line, loc._from_character));

    auto [to_line, to_character] =
        std::max(std::tie(_to_line, _to_character), std::tie(loc._to_line, loc._to_character));

    return Location(_file, from_line, to_line, from_character, to_character);
}

std::string Location::dump(bool no_path) const {
    if ( ! *this )
        return "<no location>";

    std::string lines;

    if ( _from_line >= 0 ) {
        if ( _from_character >= 0 )
            lines = util::fmt(":%d:%d", _from_line, _from_character);
        else
            lines = util::fmt(":%d", _from_line);

        if ( _to_line >= 0 ) {
            if ( _to_character >= 0 )
                lines += util::fmt("-%d:%d", _to_line, _to_character);
            else
                lines += util::fmt("-%d", _to_line);
        }
    }

    auto path = no_path ? _file.filename() : _file;
    return util::fmt("%s%s", path.generic_string(), lines);
}
