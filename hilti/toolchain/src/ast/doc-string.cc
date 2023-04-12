// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/doc-string.h>
#include <hilti/compiler/printer.h>

using namespace hilti;

std::string DocString::normalize(std::string line) const {
    line = util::trim(line);

    if ( util::startsWith(line, "##!") )
        line = line.substr(3);
    else if ( util::startsWith(line, "##<") )
        line = line.substr(3);
    else if ( util::startsWith(line, "##") )
        line = line.substr(2);

    return util::trim(line);
}

void DocString::render(std::ostream& out) const {
    for ( const auto& line : _summary )
        out << "##! " << line << std::endl;

    for ( const auto& line : _text )
        out << "## " << line << std::endl;
}

void DocString::render(printer::Stream& out) const {
    for ( const auto& line : _summary ) {
        out.beginLine();
        out << "##! " << line;
        out.endLine();
    }

    for ( const auto& line : _text ) {
        out.beginLine();
        out << "## " << line;
        out.endLine();
    }
}
