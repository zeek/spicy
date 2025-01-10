// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/declarations/type.h>

using namespace hilti;
using namespace hilti::declaration;

node::Properties declaration::Field::properties() const {
    auto p =
        node::Properties{{"cc", _cc ? to_string(*_cc) : "<unset>"}, {"linked-type", to_string(_linked_type_index)}};
    return Declaration::properties() + std::move(p);
}

std::string declaration::Field::_dump() const {
    std::vector<std::string> x;

    if ( isResolved() )
        x.emplace_back("(resolved)");
    else
        x.emplace_back("(not resolved)");

    return util::join(x);
}
