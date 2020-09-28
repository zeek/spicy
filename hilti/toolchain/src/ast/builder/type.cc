// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <vector>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctors/list.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/types/unknown.h>

using namespace hilti;

Type builder::typeOfExpressions(const std::vector<Expression>& e) {
    if ( e.empty() )
        return type::unknown;

    auto t = e.front().type();
    for ( auto i = ++e.begin(); i != e.end(); i++ ) {
        if ( i->type() != t )
            // non-homogenous list
            return type::unknown;
    }

    return t;
}
