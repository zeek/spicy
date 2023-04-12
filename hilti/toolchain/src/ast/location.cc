// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/location.h>
#include <hilti/base/util.h>

using namespace hilti;

const Location location::None;

Location::operator bool() const { return _file != location::None._file; }

std::string Location::render(bool no_path) const {
    std::string lines;

    if ( _from_line >= 0 ) {
        if ( _from_character >= 0 )
            lines = util::fmt(":%d:%d", _from_line, _from_character);
        else
            lines = util::fmt(":%d", _from_line);

        if ( _to_line >= 0 && _to_line != _from_line ) {
            if ( _to_character >= 0 )
                lines += util::fmt("-%d:%d", _to_line, _to_character);
            else
                lines += util::fmt("-%d", _to_line);
        }
    }

    auto path = no_path ? _file.filename() : _file;
    return util::fmt("%s%s", path.generic_string(), lines);
}
