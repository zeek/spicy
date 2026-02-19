// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/types/struct.h>

using namespace hilti;
using namespace hilti::type;

bool Struct::isResolved(node::CycleDetector* cd) const {
    for ( const auto& c : children<Declaration>(1, {}) ) {
        if ( ! c )
            continue;

        if ( auto* f = c->template tryAs<declaration::Field>(); f && ! f->isResolved(cd) )
            return false;

        if ( auto* p = c->template tryAs<type::function::Parameter>(); p && ! p->isResolved(cd) )
            return false;

        return true;
    }

    return true;
}

void Struct::_setSelf(ASTContext* ctx) {
    auto* qtype = QualifiedType::createExternal(ctx, as<UnqualifiedType>(), Constness::Mutable);
    auto* self = expression::Keyword::create(ctx, expression::keyword::Kind::Self,
                                             QualifiedType::create(ctx, type::ValueReference::create(ctx, qtype),
                                                                   Constness::Mutable));

    auto* decl = declaration::Expression::create(ctx, ID("self"), self, hilti::declaration::Linkage::Private, meta());

    setChild(ctx, 0, decl);
}
