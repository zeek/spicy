// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/forward.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/all.h>
#include <hilti/compiler/type-unifier.h>

using namespace hilti;
using namespace hilti::detail;

std::shared_ptr<declaration::Type> UnqualifiedType::typeDeclaration() const {
    if ( ! _declaration_index )
        return nullptr;

    return _context->lookup(_declaration_index)->as<declaration::Type>();
}

ID UnqualifiedType::typeID() const {
    if ( auto decl = typeDeclaration(); decl && decl->fullyQualifiedID() )
        return decl->fullyQualifiedID();

    return ID();
}

ID UnqualifiedType::canonicalID() const {
    if ( auto decl = typeDeclaration(); decl && decl->canonicalID() )
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
    if ( auto decl = typeDeclaration() ) {
        if ( auto a = decl->attributes()->find("&cxxname") )
            return ID{*a->valueAsString()};
    }

    return {};
}

hilti::node::Properties UnqualifiedType::properties() const {
    auto p = node::Properties{{{"unified", _unification.str()},
                               {"type", to_string(_type_index)},
                               {"declaration", to_string(_declaration_index)},
                               {"wildcard", _is_wildcard}}};
    return Node::properties() + p;
}

std::string UnqualifiedType::_dump() const {
    std::vector<std::string> x;

    x.emplace_back(this->isResolved() ? "(resolved)" : "(not resolved)");

    return util::join(x);
}

bool UnqualifiedType::unify(ASTContext* ctx, const NodePtr& scope_root) {
    return type_unifier::unify(ctx, as<UnqualifiedType>());
}

bool QualifiedType::isResolved(node::CycleDetector* cd) const {
    if ( cd && cd->haveSeen(this) )
        return true;

    auto t = _type();

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

hilti::node::Properties QualifiedType::properties() const {
    auto side = (_side == Side::LHS ? "lhs" : "rhs");
    auto constness = (_constness == Constness::Const ? "true" : "false");
    return {{"const", constness}, {"side", side}};
}

std::string QualifiedType::_dump() const {
    std::vector<std::string> x;
    return util::join(x, " ");
}

UnqualifiedTypePtr type::follow(const UnqualifiedTypePtr& t) {
    if ( auto n = t->tryAs<type::Name>() ) {
        if ( auto r = n->resolvedType() )
            return r;
    }

    return t;
}

QualifiedTypePtr QualifiedType::createExternal(ASTContext* ctx, const UnqualifiedTypePtr& t, Constness const_,
                                               const Meta& m) {
    return std::shared_ptr<QualifiedType>(new QualifiedType(ctx, {}, t, const_, Side::RHS, m));
}

QualifiedTypePtr QualifiedType::createAuto(ASTContext* ctx, const Meta& m) {
    return QualifiedTypePtr(new QualifiedType(ctx, {type::Auto::create(ctx, m)}, Constness::Mutable, Side::RHS, m));
}

QualifiedTypePtr QualifiedType::createAuto(ASTContext* ctx, Side side, const Meta& m) {
    return QualifiedTypePtr(new QualifiedType(ctx, {type::Auto::create(ctx, m)}, Constness::Mutable, side, m));
}

UnqualifiedTypePtr QualifiedType::_type() const {
    if ( _external )
        return _context->lookup(_external)->as<UnqualifiedType>();
    else
        return child<UnqualifiedType>(0);
}
