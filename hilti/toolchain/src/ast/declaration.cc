// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declaration.h>
#include <hilti/ast/visitor.h>

using namespace hilti;

Declaration::~Declaration() = default;

std::string Declaration::_dump() const {
    std::string s;

    if ( auto doc = documentation() )
        s += doc->dump();

    return s;
}
