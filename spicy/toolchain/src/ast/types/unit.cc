// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/expressions/type.h>
#include <hilti/ast/types/reference.h>

#include <spicy/ast/types/unit-items/property.h>
#include <spicy/ast/types/unit-items/sink.h>
#include <spicy/ast/types/unit-items/switch.h>
#include <spicy/ast/types/unit-items/unresolved-field.h>
#include <spicy/ast/types/unit-items/variable.h>
#include <spicy/ast/types/unit.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/codegen/grammar.h>

using namespace spicy;
using namespace spicy::type;

static NodePtr itemByNameBackend(const NodePtr& i, const ID& id) {
    if ( auto x = i->tryAs<unit::item::Field>(); x && x->id() == id )
        return i;

    if ( auto x = i->tryAs<unit::item::Variable>(); x && x->id() == id )
        return i;

    if ( auto x = i->tryAs<unit::item::Sink>(); x && x->id() == id )
        return i;

    if ( auto x = i->tryAs<unit::item::Switch>() ) {
        for ( const auto& c : x->cases() ) {
            for ( const auto& si : c->items() ) {
                if ( auto x = itemByNameBackend(si, id) )
                    return x;
            }
        }
    }

    return {};
}

UnqualifiedTypePtr Unit::contextType() const {
    if ( auto context = propertyItem("%context") )
        if ( auto ty = context->expression()->type()->type()->tryAs<hilti::type::Type_>() )
            return ty->typeValue()->type();

    return {};
}

unit::item::PropertyPtr Unit::propertyItem(const std::string& name) const {
    for ( const auto& i : items<unit::item::Property>() ) {
        if ( i->id() == name )
            return i;
    }

    return {};
}

unit::item::Properties Unit::propertyItems(const std::string& name) const {
    unit::item::Properties props;

    for ( const auto& i : items<unit::item::Property>() ) {
        if ( i->id() == name )
            props.push_back(i);
    }

    return props;
}


bool Unit::isResolved(node::CycleDetector* cd) const {
    if ( isWildcard() )
        return true;

    if ( ! self() )
        return false;

    for ( const auto& c : children() ) {
        if ( auto i = c->template tryAs<unit::Item>(); i && ! i->isResolved(cd) )
            return false;

        if ( auto p = c->template tryAs<hilti::declaration::Parameter>(); p && ! p->isResolved(cd) )
            return false;
    }

    return true;
}

unit::ItemPtr Unit::itemByName(const ID& id) const {
    for ( const auto& i : items() ) {
        if ( auto x = itemByNameBackend(i, id) )
            return x->as<unit::Item>();
    }

    return {};
}

namespace {
struct AssignItemIndicesVisitor : public visitor::PreOrder {
    void operator()(unit::item::Field* n) final {
        n->setIndex(index++);

        if ( auto sub = n->item() )
            dispatch(sub);
    }

    void operator()(unit::item::UnresolvedField* n) final {
        n->setIndex(index++);

        if ( auto sub = n->item() )
            dispatch(sub);
    }

    void operator()(unit::item::Switch* n) final {
        for ( auto& c : n->cases() ) {
            for ( auto& i : c->items() )
                dispatch(i);
        }
    }

    uint64_t index = 0;
};
} // namespace

void Unit::_assignItemIndices() {
    AssignItemIndicesVisitor assigner;

    for ( auto& item : items() )
        assigner.dispatch(item);
}

void Unit::_setSelf(ASTContext* ctx) {
    auto qtype = QualifiedType::createExternal(ctx, as<UnqualifiedType>(), hilti::Constness::NonConst);
    auto self = hilti::expression::Keyword::create(ctx, hilti::expression::keyword::Kind::Self, qtype);

    auto decl = hilti::declaration::Expression::create(ctx, ID("self"), self, {}, meta());

    setChild(ctx, 0, std::move(decl));
}
