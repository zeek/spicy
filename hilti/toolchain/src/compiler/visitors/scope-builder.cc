// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/forward.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/list-comprehension.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/unit.h>

using namespace hilti;

namespace {

struct VisitorPass1 : public visitor::PostOrder<void, VisitorPass1> {
    explicit VisitorPass1(Unit* unit) : unit(unit) {}
    Unit* unit;

    void operator()(const Module& m, position_t p) {
        Node d = Declaration(declaration::Module(NodeRef(p.node), m.meta()));
        p.node.scope()->insert(m.id(), std::move(d));
    }

    void operator()(const declaration::ImportedModule& m, position_t p) {
        auto& other = unit->imported(m.id());
        p.node = declaration::ImportedModule::setModule(m, NodeRef(other));
        p.node.setScope(other.scope());
    }

    void operator()(const type::Function& m, position_t p) {
        if ( p.parent().isA<Function>() )
            p.node.scope()->moveInto(p.parent().scope().get());
    }

    void operator()(const type::Enum& m, position_t p) {
        if ( auto t = p.parent().tryAs<declaration::Type>() ) {
            for ( const auto& l : m.labels() ) {
                auto e = expression::Ctor(ctor::Enum(l, NodeRef(p.parent()), l.meta()), l.meta());
                auto d = declaration::Constant(l.id(), std::move(e), t->linkage(), l.meta());
                p.parent().scope()->insert(l.id(), Declaration(std::move(d)));
            }
        }
    }

    void operator()(const type::Struct& m, position_t p) {
        if ( auto t = p.parent().tryAs<declaration::Type>() ) {
            auto id = ID("self", m.meta());
            auto type = type::Computed(NodeRef(p.parent()),
                                       [](Node& n) { return type::ValueReference(n.as<declaration::Type>().type()); });
            auto self = expression::Keyword(expression::keyword::Kind::Self, type, m.meta());
            auto d = declaration::Expression(id, self, declaration::Linkage::Private, m.meta());
            p.parent().scope()->insert(id, Declaration(d));

            // Make parameters accessible
            for ( auto&& x : p.node.as<type::Struct>().parameterNodes() )
                p.parent().scope()->insert(x->as<type::function::Parameter>().id(), NodeRef(x));

            for ( auto& f : m.fields() ) {
                // If &id is specified, make field directly accessible under
                // given ID (i.e., as alias to "self.[...]").
                ID id;

                if ( auto x = AttributeSet::find(f.attributes(), "&id") )
                    id = ID(*x->valueAs<std::string>(), f.meta());

                if ( id ) {
                    Expression self =
                        expression::ResolvedID("self", NodeRef(p.parent().scope()->lookup("self")->node), f.meta());

                    self = Expression(
                        operator_::value_reference::Deref::Operator().instantiate({std::move(self)}, f.meta()));

                    auto e =
                        operator_::struct_::MemberConst::Operator().instantiate({std::move(self),
                                                                                 expression::Member(f.id(), f.meta())},
                                                                                f.meta());

                    auto d = declaration::Expression(id, std::move(e), {}, declaration::Linkage::Private, f.meta());

                    p.parent().scope()->insert(id, Declaration(d));
                }

                if ( f.isStatic() ) {
                    // Insert static member into struct's namespace.
                    auto field_id = f.id();
                    auto module_id = p.template findParent<Module>()->get().id();
                    auto qualified_id = ID(module_id, t->id(), f.id());

                    std::optional<Declaration> decl;

                    if ( f.type().isA<type::Function>() ) {
                        auto wrapper = type::Computed(NodeRef(p.node), [field_id](auto n) {
                            auto t = n.template as<type::Struct>();
                            return t.field(field_id)->type();
                        });

                        auto nf = Function(f.id(), wrapper, {}, f.callingConvention());
                        decl = declaration::Function(std::move(nf), t->linkage(), m.meta());
                    }
                    else
                        // Using a local here is cheating a bit: We just need to
                        // get the ID through to codegen.
                        decl = declaration::LocalVariable(qualified_id, f.type());

                    p.parent().scope()->insert(f.id(), *decl);
                }
            }
        }
    }

    void operator()(const statement::Switch& s, position_t p) {
        auto wrapper =
            type::Computed(NodeRef(p.node), [](Node& n) { return n.template as<statement::Switch>().type(); });

        auto d = declaration::LocalVariable(ID("__x"), wrapper, {}, true, s.meta());
        p.node.scope()->insert(d.id(), Declaration(d));
    }

    void operator()(const statement::Declaration& d, position_t p) {
        p.node.scope()->moveInto(p.parent().scope().get());
    }

    void operator()(const declaration::Parameter& d, position_t p) {
        if ( p.parent(2).isA<Function>() )
            p.parent(2).scope()->insert(d.id(), NodeRef(p.node));

        if ( p.parent(1).isA<statement::try_::Catch>() )
            p.parent(1).scope()->insert(d.id(), NodeRef(p.node));
    }

    void operator()(const declaration::LocalVariable& d, position_t p) {
        if ( p.parent().isA<statement::If>() ) {
            // Statement node may be replaced later, so insert an indirect
            // reference to the local.
            NodeRef x = NodeRef(p.parent());
            auto forward =
                declaration::Forward([x]() -> Declaration { return *x->as<statement::If>().init(); }, d.meta());
            p.parent().scope()->insert(d.id(), Declaration(forward));
            return;
        }

        if ( p.parent().isA<statement::While>() ) {
            // Statement node may be replaced later, so insert an indirect
            // reference to the local.
            NodeRef x = NodeRef(p.parent());
            auto forward =
                declaration::Forward([x]() -> Declaration { return *x->as<statement::While>().init(); }, d.meta());
            p.parent().scope()->insert(d.id(), Declaration(forward));
            return;
        }

        p.parent().scope()->insert(d.id(), NodeRef(p.node));
    }

    void operator()(const expression::ListComprehension& e, position_t p) {
        if ( p.node.scope()->has(e.id()) )
            // We can encounter this node multiple times.
            return;

        auto wrapper = type::Computed(NodeRef(p.node), [](auto n) {
            const auto& lc = n.template as<expression::ListComprehension>();
            if ( lc.input().type().template isA<type::Unknown>() )
                return lc.input().type();

            if ( auto t = lc.input().type(); type::isIterable(t) )
                return t.iteratorType(true).dereferencedType();
            else
                return type::unknown;
        });

        auto d = declaration::LocalVariable(e.id(), wrapper, {}, true, e.id().meta());
        p.node.scope()->insert(d.id(), Declaration(d));
    }

    void operator()(const statement::For& s, position_t p) {
        auto wrapper = type::Computed(NodeRef(p.node), [](auto n) {
            auto t = n.template as<statement::For>().sequence().type();
            if ( t.template isA<type::Unknown>() )
                return t;

            if ( ! type::isIterable(t) )
                return type::unknown;

            return t.iteratorType(true).dereferencedType();
        });

        auto d = declaration::LocalVariable(s.id(), wrapper, {}, true, s.id().meta());
        s.scope()->insert(d.id(), Declaration(d));
    }
};

struct VisitorPass2 : public visitor::PostOrder<void, VisitorPass2> {
    explicit VisitorPass2(Unit* unit) : unit(unit) {}
    Unit* unit;

    void operator()(const Declaration& d, position_t p) {
        if ( p.parent().isA<Module>() && d.id().namespace_().empty() )
            p.parent().scope()->insert(d.id(), NodeRef(p.node));
    }
};

struct VisitorPass3 : public visitor::PostOrder<void, VisitorPass3> {
    explicit VisitorPass3(Unit* unit) : unit(unit) {}
    Unit* unit;

    std::pair<bool, std::optional<NodeRef>> lookupType(Node* u, const ID& id) {
        auto resolved = u->scope()->lookupAll(id);

        if ( resolved.empty() )
            return std::make_pair(false, std::nullopt);

        if ( resolved.size() == 1 ) {
            auto& r = resolved.front();

            if ( auto t = r.node->template tryAs<declaration::Type>() ) {
                if ( t->type().isA<type::Struct>() )
                    return std::make_pair(false, r.node);
            }

            u->addError(util::fmt("ID %s does not resolve to a type (but to %s)", id, r.node->typename_()));
            return std::make_pair(true, std::nullopt);
        }

        u->addError(util::fmt("type namespace %s is ambiguous", id));
        return std::make_pair(true, std::nullopt);
    }

    void operator()(const declaration::Function& f, position_t p) {
        if ( f.linkage() == declaration::Linkage::Struct && ! f.function().isStatic() ) {
            auto ns = f.id().namespace_();

            if ( ns.empty() ) {
                p.node.addError("method lacks a type namespace");
                return;
            }

            for ( auto i = p.path.rbegin(); i != p.path.rend(); i++ ) {
                auto [stop, node] = lookupType(&**i, ns);

                if ( stop )
                    return;

                if ( ! node )
                    continue;

                auto t = (*node)->as<declaration::Type>().type().as<type::Struct>();
                auto fields = t.fields(f.id().local());

                if ( fields.empty() ) {
                    p.node.addError(util::fmt("type %s does not have a method '%s'", ns, f.id().local()));
                    return;
                }

                bool found = false;
                for ( const auto& sf : fields ) {
                    auto sft = sf.type().tryAs<type::Function>();

                    if ( ! sft ) {
                        p.node.addError(util::fmt("%s is not a method", ID(ns, f.id().local())));
                        return;
                    }

                    if ( areEquivalent(*sft, f.function().type()) ) {
                        // Link any "auto" parameters to the declaration. When
                        // we update one later, all linked instanced will
                        // reflect the change. For types that are already
                        // resolved, we can just update any remaining auto
                        // directly.
                        auto field_params = sft->parameters();
                        auto method_params = f.function().type().parameters();

                        for ( auto&& [pf, pm] : util::zip2(field_params, method_params) ) {
                            auto af = pf.type().tryAs<type::Auto>();
                            auto am = pm.type().tryAs<type::Auto>();

                            if ( af && am )
                                am->linkTo(*af); // both will be resolved together
                            else if ( af )
                                af->typeNode() = pm.type(); // the other is already resolved
                            else if ( am )
                                am->typeNode() = pf.type(); // the other is already resolved
                        }

                        found = true;
                    }
                }

                if ( ! found ) {
                    p.node.addError(
                        util::fmt("type %s does not have a method '%s' matching the signature", ns, f.id().local()));
                    return;
                }

                p.node.setScope((*node)->scope());
                return;
            }

            p.node.addError(util::fmt("cannot resolve type namespace %s", ns));
        }
    }
};

} // anonymous namespace

void hilti::detail::clearErrors(Node* root) {
    for ( const auto&& i : hilti::visitor::PreOrder<>().walk(root) )
        i.node.clearErrors();
}

void hilti::detail::buildScopes(const std::vector<std::pair<ID, NodeRef>>& modules, Unit* unit) {
    util::timing::Collector _("hilti/compiler/scope-builder");

    // Need to run each phase on all modules first before proceeding to the
    // next as they maybe be cross-module dependencies in later phases.

    for ( auto& [id, m] : modules ) {
        auto v1 = VisitorPass1(unit);
        for ( auto i : v1.walk(&*m) )
            v1.dispatch(i);
    }

    for ( auto& [id, m] : modules ) {
        auto v2 = VisitorPass2(unit);
        for ( auto i : v2.walk(&*m) )
            v2.dispatch(i);
    }

    for ( auto& [id, m] : modules ) {
        auto v3 = VisitorPass3(unit);
        for ( auto i : v3.walk(&*m) )
            v3.dispatch(i);
    }
}
