// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/location.h>
#include <hilti/base/util.h>

using namespace hilti;

const Location location::None;

Location::operator bool() const { return _file != location::None._file; }

std::string Location::render(bool no_path) const {
    std::string lines;

    if ( _from >= 0 ) {
        lines = util::fmt(":%d", _from);

        if ( _to >= 0 && _to != _from ) {
            lines += util::fmt("-%d", _to);
        }
    }

    auto path = no_path ? _file.filename() : _file;
    return util::fmt("%s%s", path.generic_string(), lines);
}
