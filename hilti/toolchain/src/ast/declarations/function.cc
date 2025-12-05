// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/operators/function.h>
#include <hilti/ast/types/operand-list.h>
#include <hilti/ast/types/struct.h>

using namespace hilti;
using namespace hilti::declaration;

node::Properties declaration::Function::properties() const {
    auto p = node::Properties{{"operator", (_operator ? "<set>" : "<unset>")},
                              {"linked-declaration", to_string(_linked_declaration_index)},
                              {"linked-prototype", to_string(_linked_prototype_index)}};

    return Declaration::properties() + std::move(p);
}

ID declaration::Function::functionID(ASTContext* ctx) const {
    if ( auto* prototype = ctx->lookup(linkedPrototypeIndex()) )
        return prototype->fullyQualifiedID();

    return fullyQualifiedID();
}
