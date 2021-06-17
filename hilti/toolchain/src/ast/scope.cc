// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/id.h>
#include <hilti/ast/scope.h>

using namespace hilti;

void Scope::insert(const ID& id, NodeRef n) {
    auto& nodes = _items[std::string(id)];
    nodes.push_back(std::move(n));
}

void Scope::insert(const ID& id, Node&& n) {
    auto p = std::make_shared<Node>(std::move(n));
    _nodes.push_back(p);
    insert(id, NodeRef(*_nodes.back()));
}

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

static auto createRefs(std::vector<NodeRef> refs, const std::string& id, bool external) {
    std::vector<Scope::Referee> result;

    result.reserve(refs.size());
    for ( auto& n : refs ) {
        result.push_back(Scope::Referee{.node = std::move(n), .qualified = id, .external = external});
    }

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
                Scope* scope_ = (*v).scope().get();

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
            auto s = util::fmt("%s%s -> %s", prefix, k, x ? x->render(false) : "<invalid ref>");

            if ( x ) {
                if ( auto d = x->tryAs<declaration::Expression>() )
                    s += util::fmt(" (type: %s)", d->expression().type());
            }

            out << s << '\n';
        }
    }
}
