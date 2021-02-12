// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/id.h>
#include <hilti/ast/expressions/type.h>
#include <hilti/ast/expressions/typeinfo.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/types/id.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>
#include <hilti/global.h>

using namespace hilti;

namespace {

inline const hilti::logging::DebugStream Resolver("resolver");

struct Visitor : public visitor::PreOrder<void, Visitor> {
    explicit Visitor(Unit* unit) : unit(unit) {}
    Unit* unit;
    ID module_id = ID("<no module>");
    bool modified = false;

    template<typename T>
    void replaceNode(position_t* p, T&& n, int line, bool set_modified = true) {
        p->node = std::forward<T>(n);
        if ( set_modified ) {
            HILTI_DEBUG(Resolver, hilti::util::fmt("  modified by HILTI %s/%d",
                                                   hilti::rt::filesystem::path(__FILE__).filename().native(), line))
            modified = true;
        }
    }

#if 0
    void preDispatch(const Node& n, int level) override {
        auto indent = std::string(level * 2, ' ');
        std::cerr << "# " << indent << "> " << n.render() << std::endl;
        n.scope()->render(std::cerr, "    | ");
    }
#endif

    void operator()(const Module& m) { module_id = m.id(); }

    void operator()(const type::UnresolvedID& u, position_t p) {
        auto resolved = scope::lookupID<declaration::Type>(u.id(), p);

        if ( ! resolved ) {
            p.node.addError(resolved.error());
            return;
        }

        Type t = type::ResolvedID(resolved->second, NodeRef(resolved->first), u.meta());

        if ( resolved->first->as<declaration::Type>().isOnHeap() ) {
            // TODO(robin): This logic is pretty brittle as we need make sure
            // to skip the transformation for certain AST nodes. Not sure how
            // to improve this.
            auto pc = p.parent().tryAs<Ctor>();
            auto pe = p.parent().tryAs<Expression>();
            auto pt = p.parent().tryAs<Type>();

            auto replace = true;

            if ( pt && type::isReferenceType(*pt) )
                replace = false;

            if ( pc && type::isReferenceType(pc->type()) )
                replace = false;

            if ( pc && pc->isA<ctor::Default>() )
                replace = false;

            if ( pe && pe->isA<expression::Type_>() )
                replace = false;

            if ( pe && pe->isA<expression::ResolvedOperator>() ) {
                if ( pe->isA<operator_::value_reference::Deref>() )
                    replace = false;

                if ( pe->isA<operator_::strong_reference::Deref>() )
                    replace = false;

                if ( pe->isA<operator_::weak_reference::Deref>() )
                    replace = false;
            }

            if ( pe && pe->isA<expression::UnresolvedOperator>() ) {
                if ( pe->as<expression::UnresolvedOperator>().kind() == operator_::Kind::Deref )
                    replace = false;
            }

            if ( pe && pe->isA<expression::TypeInfo>() )
                replace = false;

            if ( replace )
                t = type::ValueReference(t, Location("<on-heap-replacement>"));
        }

        replaceNode(&p, t, __LINE__);
    }

    void operator()(const type::Computed& u, position_t p) {
        // As soon as we now the computed type, we swap it in.
        if ( auto t = u.type(); ! t.isA<type::Unknown>() ) {
            if ( auto id = t.typeID() )
                replaceNode(&p, type::UnresolvedID(*id, p.node.meta()), __LINE__);
            else
                replaceNode(&p, t, __LINE__);
        }
    }

    void operator()(const expression::UnresolvedID& u, position_t p) {
        auto resolved = scope::lookupID<Declaration>(u.id(), p);

        if ( ! resolved ) {
            p.node.addError(resolved.error());
            return;
        }

        if ( auto t = resolved->first->tryAs<declaration::Type>() ) {
            auto nt = type::setTypeID(t->type(), resolved->second);
            if ( ! t->typeID() )
                *resolved->first = declaration::Type::setType(*t, nt);

            replaceNode(&p, expression::Type_(nt, u.meta()), __LINE__);
            return;
        }

        // If we are inside a call expression, leave it alone. The operator
        // resolver will take care of that.
        if ( auto op = p.parent().tryAs<expression::UnresolvedOperator>(); op && op->kind() == operator_::Kind::Call )
            return;

        replaceNode(&p, expression::ResolvedID(resolved->second, NodeRef(resolved->first), u.meta()), __LINE__);
    }

    void operator()(const expression::ResolvedID& u, position_t p) {
        auto& parent = p.parent();
        if ( auto op = parent.tryAs<expression::ResolvedOperator>();
             op && op->operator_().kind() == operator_::Kind::Call )
            return;

        if ( auto op = parent.tryAs<expression::UnresolvedOperator>(); op && op->kind() == operator_::Kind::Call )
            // If we are inside a call expression, leave it alone. The operator
            // resolver will take care of that.
            return;

        // Look it up again because the AST may have changed the mapping.
        //
        // TODO(robin): Not quite sure in which cases this happen, ideally it
        // shouldn't be necessary to re-lookup an ID once it has been
        // resolved.
        auto resolved = scope::lookupID<Declaration>(u.id(), p);

        if ( ! resolved )
            return;

        // We replace the node, but don't flag the AST as modified because that
        // could loop.
        //
        // Note: We *always* make the replacement even if nothing has changed
        // because it's actually expensive to find out if the new node
        // differs from the old. Originally, there was an if-statement (*)
        // here, but it turns out that's super-expensive in terms of CPU
        // performance, presumably because it needs to cycle through
        // potentially large ASTs for the comparision. There was some
        // evidence that it's expensive only in a debug build, but I didn't
        // further investigate; just always doing the replacement seems to be
        // the cheapest approach either way.
        //
        // (*) if ( (! u.isValid()) || u.declaration() != resolved->first->as<Declaration>() )
        replaceNode(&p, expression::ResolvedID(resolved->second, NodeRef(resolved->first), u.meta()), __LINE__, false);
    }

    void operator()(const declaration::Type& d, position_t p) {
        auto type_id = ID(module_id, d.id());

        std::optional<ID> cxx_id;

        if ( auto a = AttributeSet::find(d.attributes(), "&cxxname") )
            cxx_id = *a->valueAs<std::string>();

        if ( d.type().typeID() != type_id ) {
            auto nt = type::setTypeID(d.type(), std::move(type_id));

            if ( cxx_id && d.cxxID() != *cxx_id )
                nt = type::setCxxID(nt, std::move(*cxx_id));

            replaceNode(&p, declaration::Type::setType(d, nt), __LINE__);
        }

        else if ( cxx_id && d.cxxID() != *cxx_id ) {
            auto nt = type::setCxxID(d.type(), std::move(*cxx_id));
            replaceNode(&p, declaration::Type::setType(d, nt), __LINE__);
        }
    }
};

} // anonymous namespace

bool hilti::detail::resolveIDs(Node* root, Unit* unit) {
    util::timing::Collector _("hilti/compiler/id-resolver");

    auto v = Visitor(unit);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified;
}
