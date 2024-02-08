// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/doc-string.h>
#include <hilti/base/util.h>
#include <hilti/compiler/printer.h>

using namespace hilti;
using namespace hilti::detail;

std::string DocString::_normalize(std::string line) const {
    line = util::trim(line);

    if ( util::startsWith(line, "##!") )
        line = line.substr(3);
    else if ( util::startsWith(line, "##<") )
        line = line.substr(3);
    else if ( util::startsWith(line, "##") )
        line = line.substr(2);

    return util::trim(line);
}

void DocString::print(std::ostream& out) const {
    for ( const auto& line : _summary )
        out << "##! " << line << '\n';

    for ( const auto& line : _text )
        out << "## " << line << '\n';
}

void DocString::print(printer::Stream& out) const {
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

std::string DocString::dump() const {
    const int max_doc = 40;
    std::string rendering;

    auto summary_ = util::join(summary(), " ");
    if ( ! summary_.empty() ) {
        auto summary_dots = (summary_.size() > max_doc || summary().size() > 1 ? "..." : "");
        rendering += util::fmt(R"(summary: "%s%s")", summary_.substr(0, max_doc), summary_dots);
    }

    auto text_ = util::join(text(), " ");
    if ( ! text_.empty() ) {
        if ( ! rendering.empty() )
            rendering += " ";

        auto text_dots = (text_.size() > max_doc || text().size() > 1 ? "..." : "");
        rendering += util::fmt(R"(doc: "%s%s")", text_.substr(0, max_doc), text_dots);
    }

    return util::fmt(" (%s)", rendering);
}
