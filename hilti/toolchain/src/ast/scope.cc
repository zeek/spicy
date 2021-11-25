// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/id.h>
#include <hilti/ast/scope.h>

using namespace hilti;

void Scope::insert(ID id, NodeRef&& n) {
    assert(n && n->isA<Declaration>());
    const auto& d = n->as<Declaration>();
    auto& nodes = _items[std::move(id)];

    // Filter out duplicates
    for ( const auto& i : nodes ) {
        if ( i && i->as<Declaration>() == d )
            return;
    }

    nodes.push_back(std::move(n));
}

void Scope::insert(NodeRef&& n) {
    assert(n && n->isA<Declaration>());
    const auto& d = n->as<Declaration>();
    insert(d.id(), std::move(n));
}

void Scope::insertNotFound(ID id) { _items[std::move(id)] = {NodeRef(node::none)}; }

static auto createRefs(const std::vector<Scope::Referee>& refs, const std::string& ns, bool external) {
    std::vector<Scope::Referee> result;

    result.reserve(refs.size());
    for ( auto r : refs ) {
        result.push_back(Scope::Referee{.node = std::move(r.node),
                                        .qualified = (ns + "::" + r.qualified),
                                        .external = (external || r.external)});
    }

    return result;
}

static auto createRefs(const std::vector<NodeRef>& refs, const std::string& id, bool external) {
    std::vector<Scope::Referee> result;

    result.reserve(refs.size());
    for ( auto& n : refs )
        result.push_back(Scope::Referee{.node = NodeRef(n), .qualified = id, .external = external});

    return result;
}


std::vector<Scope::Referee> Scope::_findID(const Scope* scope, const ID& id, bool external) const {
    // Try all subpaths.
    //
    // TOOD: This method needs a cleanup, pretty ugly.
    std::string h = id;
    std::string t = "$ $"; // non-empty, illegal-ID dummy

    std::vector<Scope::Referee> result;

    while ( true ) {
        if ( t.empty() )
            return {};

        if ( auto i = scope->_items.find(h); i != scope->_items.end() ) {
            if ( t == "$ $" )
                return createRefs(i->second, h, external);

            for ( const auto& v : (*i).second ) {
                Scope* scope_ = v->scope().get();

                if ( auto m = v->tryAs<declaration::Module>() )
                    scope_ = m->root().scope().get();

                auto e = v->isA<declaration::ImportedModule>();

                if ( auto x = _findID(scope_, ID(t), external || e); ! x.empty() )
                    return createRefs(x, h, external);
            }

            return {};
        }

        std::string nt;
        std::tie(h, nt) = util::rsplit1(h, "::");
        t = (! t.empty() && ! nt.empty() && t != "$ $" ? util::fmt("%s::%s", nt, t) : nt);
    }
}

std::vector<Scope::Referee> Scope::_findID(const ID& id, bool external) const { return _findID(this, id, external); }

void Scope::render(std::ostream& out, const std::string& prefix) const {
    for ( const auto& [k, v] : items() ) {
        for ( const auto& x : v ) {
            if ( ! x ) {
                out << util::fmt("%s%s -> <invalid-ref>\n", prefix, k);
                continue;
            }

            auto s = util::fmt("%s%s -> %s", prefix, k, x->render(false));

            if ( x ) {
                if ( auto d = x->tryAs<declaration::Expression>() )
                    s += util::fmt(" (type: %s @t:%p)", d->expression().type(), d->expression().type().identity());
                else
                    s += util::fmt(" ([@d:%p])", x->identity());
            }

            out << s << '\n';
        }
    }
}
