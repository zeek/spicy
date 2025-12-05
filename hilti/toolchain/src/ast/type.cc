// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/forward.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/all.h>
#include <hilti/compiler/type-unifier.h>

using namespace hilti;
using namespace hilti::detail;

declaration::Type* UnqualifiedType::typeDeclaration() const {
    if ( ! _declaration_index )
        return nullptr;

    return _context->lookup(_declaration_index)->as<declaration::Type>();
}

ID UnqualifiedType::typeID() const {
    if ( auto* decl = typeDeclaration(); decl && decl->fullyQualifiedID() )
        return decl->fullyQualifiedID();

    return ID();
}

ID UnqualifiedType::canonicalID() const {
    if ( auto* decl = typeDeclaration(); decl && decl->canonicalID() )
        return decl->canonicalID();

    return ID();
}

bool UnqualifiedType::isOnHeap() const {
    if ( _declaration_index )
        return typeDeclaration()->isOnHeap();
    else
        return false;
}

ID UnqualifiedType::cxxID() const {
    if ( auto* decl = typeDeclaration() ) {
        if ( auto* a = decl->attributes()->find(hilti::attribute::kind::Cxxname) )
            return ID{*a->valueAsString()};
    }

    return {};
}

hilti::node::Properties UnqualifiedType::properties() const {
    auto p = node::Properties{{{"unified", _unification.str()},
                               {"type", to_string(_type_index)},
                               {"declaration", to_string(_declaration_index)},
                               {"wildcard", _is_wildcard}}};
    return Node::properties() + std::move(p);
}

std::string UnqualifiedType::_dump() const {
    std::vector<std::string> x;

    x.emplace_back(this->isResolved() ? "(resolved)" : "(not resolved)");

    return util::join(x);
}

bool UnqualifiedType::unify(ASTContext* ctx, Node* scope_root) {
    return type_unifier::unify(ctx, as<UnqualifiedType>());
}

bool QualifiedType::isResolved(node::CycleDetector* cd) const {
    if ( cd && cd->haveSeen(this) )
        return true;

    auto* t = _type();

    if ( _external && ! cd ) {
        node::CycleDetector cd;
        cd.recordSeen(this);
        return t->isResolved(&cd);
    }

    if ( cd )
        cd->recordSeen(this);

    return t->isResolved(cd);
}

bool QualifiedType::isAuto() const { return type()->isA<type::Auto>(); }

type::Name* QualifiedType::alias() const { return _type()->tryAs<type::Name>(); }

QualifiedType* QualifiedType::innermostType() {
    if ( type()->isReferenceType() )
        return type()->dereferencedType()->innermostType();

    if ( type()->iteratorType() )
        return type()->elementType()->innermostType();

    return this;
}

hilti::node::Properties QualifiedType::properties() const {
    const auto* side = (_side == Side::LHS ? "lhs" : "rhs");
    const auto* constness = (_constness == Constness::Const ? "true" : "false");
    const auto* external = (_external ? "true" : "false");
    return {{"const", constness}, {"side", side}, {"extern", external}};
}

std::string QualifiedType::_dump() const {
    std::vector<std::string> x;
    return util::join(x, " ");
}

UnqualifiedType* type::follow(UnqualifiedType* t) {
    if ( auto* n = t->tryAs<type::Name>() ) {
        if ( auto* r = n->resolvedType() )
            return r;
    }

    return t;
}

QualifiedType* QualifiedType::createExternal(ASTContext* ctx, UnqualifiedType* t, Constness const_, const Meta& m) {
    return createExternal(ctx, t, const_, Side::RHS, m);
}

QualifiedType* QualifiedType::createExternal(ASTContext* ctx, UnqualifiedType* t, Constness const_, Side side,
                                             const Meta& m) {
    return ctx->make<QualifiedType>(ctx, {}, t, const_, side, m);
}

QualifiedType* QualifiedType::createAuto(ASTContext* ctx, const Meta& m) {
    return ctx->make<QualifiedType>(ctx, {type::Auto::create(ctx, m)}, Constness::Mutable, Side::RHS, m);
}

QualifiedType* QualifiedType::createAuto(ASTContext* ctx, Side side, const Meta& m) {
    return ctx->make<QualifiedType>(ctx, {type::Auto::create(ctx, m)}, Constness::Mutable, side, m);
}

UnqualifiedType* QualifiedType::_type() const {
    if ( _external )
        return _context->lookup(_external)->as<UnqualifiedType>();
    else
        return child<UnqualifiedType>(0);
}
