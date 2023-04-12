// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/id.h>

using namespace hilti;

bool expression::isResolved(const detail::Expression& e, type::ResolvedState* rstate) {
    // We always consider `self` expressions as fully resolved to break the
    // cycle with the type that they are pointing to.
    if ( auto id = e.tryAs<expression::ResolvedID>(); id && id->id() == ID("self") )
        return true;

    return type::detail::isResolved(e.type(), rstate);
}
