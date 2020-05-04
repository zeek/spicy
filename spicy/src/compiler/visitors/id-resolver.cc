// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/types/id.h>
#include <hilti/ast/types/reference.h>
#include <hilti/global.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit-items/unresolved-field.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace {

template<typename T>
auto resolveField(const type::unit::item::UnresolvedField& u, const T& t) { // TODO(google-runtime-references)
    return type::unit::item::Field(u.fieldID(), std::move(t), u.engine(), u.arguments(), u.repeatCount(), u.sinks(),
                                   u.attributes(), u.condition(), u.hooks(), u.meta());
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

    void operator()(const type::unit::item::UnresolvedField& u, position_t p) {
        if ( auto id = u.unresolvedID() ) {
            auto resolved = hilti::lookupID<hilti::Declaration>(*id, p);

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
                    tt = hilti::type::ValueReference(tt);

                replaceNode(&p, resolveField(u, tt));
                return;
            }

            if ( auto c = resolved->first->tryAs<hilti::declaration::Constant>() ) {
                if ( auto ctor = c->value().tryAs<hilti::expression::Ctor>() )
                    replaceNode(&p, resolveField(u, ctor->ctor()));
                else
                    p.node.addError("field value must be a constant");

                return;
            }

            p.node.addError(util::fmt("field value must be a constant or type, but is a %s",
                                      resolved->first->as<hilti::Declaration>().displayName()));
        }

        else if ( auto c = u.ctor() )
            replaceNode(&p, resolveField(u, *c));

        else if ( auto t = u.type() )
            replaceNode(&p, resolveField(u, *t));

        else if ( auto i = u.item() )
            replaceNode(&p, resolveField(u, *i));

        else
            hilti::logger().internalError("no known typw for unresolved field");
    }

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
            auto f = p.findParent<type::unit::item::Field>();

            if ( ! f )
                return;

            Type dd;

            if ( auto t = p.findParent<spicy::Hook>() ) {
                // Inside a field's hook.
                if ( t->get().isForEach() )
                    dd = type::Computed(hilti::builder::memberCall(hilti::builder::member(hilti::builder::id("self"),
                                                                                          f->get().id()),
                                                                   "front", {}),
                                        false);
                else
                    dd = f->get().itemType();
            }

            else if ( auto a = p.findParent<Attribute>() ) {
                // Inside an attribute expression.
                if ( a->get().tag() == "&until" || a->get().tag() == "&until-including" || a->get().tag() == "&while" )
                    dd = type::Computed(hilti::builder::memberCall(hilti::builder::member(hilti::builder::id("self"),
                                                                                          f->get().id()),
                                                                   "front", {}),
                                        false);
                else {
                    dd = f->get().parseType();

                    if ( auto bf = dd.tryAs<type::Bitfield>() )
                        dd = type::UnsignedInteger(bf->width(), bf->meta());
                }
            }

            else {
                p.node.addError("$$ not supported here");
                return;
            }

            replaceNode(&p,
                        hilti::expression::Keyword(hilti::expression::keyword::Kind::DollarDollar, dd, p.node.meta()));
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
    util::timing::Collector _("spicy/compiler/id-resolver");

    auto v1 = Visitor1(unit);
    for ( auto i : v1.walk(root) )
        v1.dispatch(i);

    auto v2 = Visitor2(unit);
    for ( auto i : v2.walk(root) )
        v2.dispatch(i);

    return v1.modified || v2.modified;
}
