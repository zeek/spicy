// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declaration.h>

using namespace hilti;

void declaration::DocString::clear() {
    _summary.clear();
    _text.clear();
}

std::string declaration::DocString::normalize(std::string line) const {
    line = util::trim(line);

    if ( util::startsWith(line, "##!") )
        line = line.substr(3);
    else if ( util::startsWith(line, "##<") )
        line = line.substr(3);
    else if ( util::startsWith(line, "##") )
        line = line.substr(2);

    return util::trim(line);
}

void declaration::DocString::render(std::ostream& out) const {
    for ( const auto& line : _summary )
        out << "##! " << line << std::endl;

    for ( const auto& line : _text )
        out << "## " << line << std::endl;
}
