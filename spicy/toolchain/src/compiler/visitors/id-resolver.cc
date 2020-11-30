// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/types/id.h>
#include <hilti/ast/types/reference.h>
#include <hilti/global.h>

#include <spicy/ast/declarations/unit-field.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/unresolved-field.h>
#include <spicy/compiler/detail/visitors.h>

#include "base/util.h"

using namespace spicy;

namespace {

// Turns an unresolved field into a resolved field.
template<typename T>
auto resolveField(const type::unit::item::UnresolvedField& u, const T& t) {
    auto field = type::unit::item::Field(u.fieldID(), std::move(t), u.engine(), u.arguments(), u.repeatCount(),
                                         u.sinks(), u.attributes(), u.condition(), u.hooks(), u.meta());

    assert(u.index());
    return type::unit::item::Field::setIndex(std::move(field), *u.index());
}

// Turns an unresolved field into a resolved field for fields that pull from a
// field declaration. This function merges the pieces from the unresolved field
// and the declaration into the resolved field as appropriate.
template<typename T>
auto resolveField(const type::unit::item::UnresolvedField& u, const T& t, declaration::UnitField declared_field) {
    // Transfer type and attributes from the field declaration, and merge any
    // hooks together.
    auto field = type::unit::item::Field(u.fieldID(), t, u.engine(), u.arguments(), declared_field.repeatCount(),
                                         u.sinks(), declared_field.attributes(), u.condition(),
                                         hilti::util::concat(declared_field.hooks(), u.hooks()), u.meta());

    assert(u.index());
    return type::unit::item::Field::setIndex(std::move(field), *u.index());
}

struct Visitor1 : public hilti::visitor::PostOrder<void, Visitor1> {
    explicit Visitor1(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;
    bool modified = false;

    template<typename T>
    void replaceNode(position_t* p, T&& n) {
        p->node = std::forward<T>(n);
        modified = true;
    }

    void replaceUnresolvedField(const type::unit::item::UnresolvedField& u, position_t p) {
        if ( auto c = u.ctor() )
            replaceNode(&p, resolveField(u, *c));

        else if ( auto t = u.type() )
            replaceNode(&p, resolveField(u, *t));

        else if ( auto i = u.item() )
            replaceNode(&p, resolveField(u, *i));

        else if ( auto id = u.unresolvedID() ) {
            auto resolved = hilti::scope::lookupID<hilti::Declaration>(*id, p);

            if ( ! resolved ) {
                p.node.addError(resolved.error());
                return;
            }

            if ( auto t = resolved->first->tryAs<hilti::declaration::Type>() ) {
                // Because we're doing type resolution ourselves here, we
                // need to account for any &on-heap attribute. Normally,
                // HILTI would take care of that for us when resolving a
                // type.
                Type tt = hilti::type::ResolvedID(*id, NodeRef(resolved->first), u.meta());

                if ( t->type().isA<type::Unit>() || AttributeSet::has(t->attributes(), "&on-heap") )
                    tt = hilti::type::ValueReference(tt, u.meta());

                replaceNode(&p, resolveField(u, tt));
            }

            else if ( auto c = resolved->first->tryAs<hilti::declaration::Constant>() ) {
                if ( auto ctor = c->value().tryAs<hilti::expression::Ctor>() )
                    replaceNode(&p, resolveField(u, ctor->ctor()));
                else
                    p.node.addError("field value must be a constant");
            }

            else if ( auto d = resolved->first->tryAs<spicy::declaration::UnitField>() ) {
                if ( auto x = d->type() )
                    replaceNode(&p, resolveField(u, *x, *d));

                else if ( auto x = d->ctor() )
                    replaceNode(&p, resolveField(u, *x, *d));

                else if ( auto x = d->item() )
                    replaceNode(&p, resolveField(u, *x, *d));

                else if ( auto x = d->unresolvedID() ) {
                    auto dummy_unresolved =
                        type::unit::item::UnresolvedField(u.fieldID(), *x, u.engine(), u.arguments(), d->repeatCount(),
                                                          u.sinks(), d->attributes(), u.condition(), d->hooks(),
                                                          u.meta());

                    auto u2 = type::unit::item::UnresolvedField::setIndex(std::move(dummy_unresolved), *u.index());
                    replaceUnresolvedField(std::move(u2), p); // recurse
                }

                else
                    hilti::logger().internalError("no known type for unit field declaration", p.node.location());
            }
            else
                p.node.addError(
                    hilti::util::fmt("field value must be a constant, type, or field declaration (but is a %s)",
                                     resolved->first->as<hilti::Declaration>().displayName()));
        }

        else
            hilti::logger().internalError("no known type for unresolved field", p.node.location());
    }

    void operator()(const type::unit::item::UnresolvedField& u, position_t p) { replaceUnresolvedField(u, p); }

    void operator()(const type::Unit& n, position_t p) {
        if ( auto t = p.parent().tryAs<hilti::declaration::Type>();
             ! t && ! p.parent(2).tryAs<hilti::declaration::Type>() )
            replaceNode(&p, hilti::type::UnresolvedID(*n.typeID(), p.node.meta()));
    }
};

struct Visitor2 : public hilti::visitor::PostOrder<void, Visitor2> {
    explicit Visitor2(hilti::Unit* unit) : unit(unit) {}
    hilti::Unit* unit;
    bool modified = false;

    template<typename T>
    void replaceNode(position_t* p, T&& n) {
        p->node = std::forward<T>(n);
        modified = true;
    }

    void operator()(const hilti::expression::Keyword& n, position_t p) {
        if ( n.kind() == hilti::expression::keyword::Kind::DollarDollar && n.type().isA<type::Unknown>() ) {
            std::optional<Type> dd;

            if ( auto f = p.findParent<hilti::Function>() ) {
                for ( const auto& p : f->get().type().parameters() ) {
                    if ( p.id() == ID("__dd") ) {
                        // Inside a free function that defines a "__dd" parameter; use it.
                        dd = hilti::type::Computed(hilti::builder::id("__dd"));
                        break;
                    }
                }
            }

            if ( ! dd ) {
                auto f = p.findParent<type::unit::item::Field>();

                if ( ! f )
                    return;

                if ( auto t = p.findParent<spicy::Hook>() ) {
                    // Inside a field's hook.
                    if ( t->get().isForEach() )
                        dd = type::unit::item::Field::vectorElementTypeThroughSelf(f->get().id());
                    else
                        dd = f->get().itemType();
                }

                else if ( auto a = p.findParent<Attribute>() ) {
                    // Inside an attribute expression.
                    if ( a->get().tag() == "&until" || a->get().tag() == "&until-including" ||
                         a->get().tag() == "&while" )
                        dd = type::unit::item::Field::vectorElementTypeThroughSelf(f->get().id());
                    else {
                        dd = f->get().parseType();

                        if ( auto bf = dd->tryAs<type::Bitfield>() )
                            dd = type::UnsignedInteger(bf->width(), bf->meta());
                    }
                }
            }

            if ( dd )
                replaceNode(&p, hilti::expression::Keyword(hilti::expression::keyword::Kind::DollarDollar, *dd,
                                                           p.node.meta()));
            else {
                p.node.addError("$$ not supported here");
                return;
            }
        }
    }

    void operator()(const type::Unit& n, position_t p) {
        if ( auto t = p.parent().tryAs<hilti::declaration::Type>();
             ! t && ! p.parent(2).tryAs<hilti::declaration::Type>() )
            replaceNode(&p, hilti::type::UnresolvedID(*n.typeID(), p.node.meta()));
    }
};

} // anonymous namespace

bool spicy::detail::resolveIDs(hilti::Node* root, hilti::Unit* unit) {
    hilti::util::timing::Collector _("spicy/compiler/id-resolver");

    auto v1 = Visitor1(unit);
    for ( auto i : v1.walk(root) )
        v1.dispatch(i);

    auto v2 = Visitor2(unit);
    for ( auto i : v2.walk(root) )
        v2.dispatch(i);

    return v1.modified || v2.modified;
}
