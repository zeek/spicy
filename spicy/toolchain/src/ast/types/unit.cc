// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/expressions/type.h>
#include <hilti/ast/types/bitfield.h>
#include <hilti/ast/types/reference.h>

#include <spicy/ast/types/unit-items/block.h>
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

static Node* itemByNameBackend(spicy::type::unit::Item* i, const ID& id) {
    if ( i->id() == id &&
         (i->isA<unit::item::Field>() || i->isA<unit::item::Variable>() || i->isA<unit::item::Sink>()) )
        return i;

    if ( auto* x = i->tryAs<unit::item::Switch>() ) {
        for ( const auto& c : x->cases() ) {
            if ( auto* x = itemByNameBackend(c->block(), id) )
                return x;
        }
    }

    if ( auto* x = i->tryAs<unit::item::Block>() ) {
        for ( const auto& si : x->allItems() ) {
            if ( auto* x = itemByNameBackend(si, id) )
                return x;
        }
    }

    return {};
}

unit::item::Property* Unit::propertyItem(const std::string& name) const {
    for ( const auto& i : items<unit::item::Property>() ) {
        if ( i->id() == ID(name) )
            return i;
    }

    return {};
}

unit::item::Properties Unit::propertyItems(const std::string& name) const {
    unit::item::Properties props;

    for ( const auto& i : items<unit::item::Property>() ) {
        if ( i->id() == ID(name) )
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
        if ( ! c )
            continue;

        if ( auto* i = c->template tryAs<unit::Item>(); i && ! i->isResolved(cd) )
            return false;

        if ( auto* p = c->template tryAs<hilti::declaration::Parameter>(); p && ! p->isResolved(cd) )
            return false;
    }

    return true;
}

unit::Item* Unit::itemByName(const ID& id) const {
    for ( const auto& i : items() ) {
        if ( auto* x = itemByNameBackend(i, id) )
            return x->as<unit::Item>();
    }

    return {};
}

static std::pair<unit::item::Field*, hilti::type::bitfield::BitRange*> findRangeInAnonymousBitField(
    const hilti::node::Set<type::unit::Item>& items, const ID& id) {
    for ( const auto& item : items ) {
        if ( auto* field = item->tryAs<type::unit::item::Field>() ) {
            if ( ! field->isAnonymous() )
                continue;

            auto* t = field->originalType()->type()->tryAs<hilti::type::Bitfield>();
            if ( ! t )
                continue;

            if ( auto* bits = t->bits(id) )
                return std::make_pair(field, bits);
        }

        else if ( auto* field = item->tryAs<type::unit::item::Switch>() ) {
            for ( const auto* c : field->cases() ) {
                if ( auto result = findRangeInAnonymousBitField({c->block()}, id); result.first )
                    return result;
            }
        }

        else if ( auto* field = item->tryAs<type::unit::item::Block>() ) {
            if ( auto result = findRangeInAnonymousBitField(field->allItems(), id); result.first )
                return result;
        }
    }

    return {};
}

std::pair<unit::item::Field*, hilti::type::bitfield::BitRange*> Unit::findRangeInAnonymousBitField(const ID& id) const {
    return ::findRangeInAnonymousBitField(items(), id);
}

namespace {
struct AssignItemIndicesVisitor : public visitor::PreOrder {
    void operator()(unit::item::Block* n) final {
        for ( auto* i : n->allItems() )
            dispatch(i);
    }

    void operator()(unit::item::Field* n) final {
        n->setIndex(index++);

        if ( auto* sub = n->item() )
            dispatch(sub);
    }

    void operator()(unit::item::UnresolvedField* n) final {
        n->setIndex(index++);

        if ( auto* sub = n->item() )
            dispatch(sub);
    }

    void operator()(unit::item::Switch* n) final {
        for ( auto* c : n->cases() )
            dispatch(c->block());
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
    auto* qtype = QualifiedType::createExternal(ctx, as<UnqualifiedType>(), hilti::Constness::Mutable);
    auto* self = hilti::expression::Keyword::create(ctx, hilti::expression::keyword::Kind::Self, qtype);

    auto* decl =
        hilti::declaration::Expression::create(ctx, ID("self"), self, hilti::declaration::Linkage::Private, meta());

    setChild(ctx, 0, decl);
}
