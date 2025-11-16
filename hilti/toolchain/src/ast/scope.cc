// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/rt/util.h>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/id.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/type.h>


using namespace hilti;

bool Scope::insert(const ID& id, Declaration* d) {
    if ( const auto& i = _items.find(id); i != _items.end() ) {
        if ( i->second.contains(d) )
            return false;
        else
            i->second.insert(d);
    }
    else
        _items[std::string(id)].insert(d);

    return true;
}

bool Scope::insert(Declaration* d) { return insert(d->id(), d); }

bool Scope::insertNotFound(const ID& id) {
    if ( const auto& i = _items.find(id); i != _items.end() ) {
        if ( i->second.contains(nullptr) )
            return false;
        else
            i->second = {nullptr};
    }
    else
        _items[id] = {nullptr};

    return true;
}

static auto createRefs(const std::vector<Scope::Referee>& refs, const std::string& ns, bool external) {
    std::vector<Scope::Referee> result;

    result.reserve(refs.size());
    for ( const auto& r : refs ) {
        result.push_back(Scope::Referee{.node = r.node,
                                        .qualified = (ns + "::" + r.qualified),
                                        .external = (external || r.external)});
    }

    return result;
}

template<typename NodeSet>
static auto createRefs(const NodeSet& refs, const std::string& id, bool external) {
    std::vector<Scope::Referee> result;
    result.reserve(refs.size());

    std::transform(refs.begin(), refs.end(), std::back_inserter(result),
                   [&](const auto& n) { return Scope::Referee{.node = n, .qualified = id, .external = external}; });

    return result;
}


std::vector<Scope::Referee> Scope::_findID(const Scope* scope, const ID& id, bool external) const {
    if ( ! scope )
        return {};

    // Try all subpaths.
    //
    // TODO: This method needs a cleanup, pretty ugly.
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
                Scope* scope_ = v->scope();

                if ( auto* m = v->tryAs<declaration::Module>() )
                    scope_ = m->scope();

                auto e = v->isA<declaration::ImportedModule>();

                if ( auto x = _findID(scope_, ID(t), external || e); ! x.empty() )
                    return createRefs(x, h, external);
            }

            return {};
        }

        std::string nt;
        std::tie(h, nt) = util::rsplit1(h, "::");
        t = (! t.empty() && ! nt.empty() && t != "$ $" ? util::fmt("%s::%s", nt, t) : std::move(nt));
    }
}

std::vector<Scope::Referee> Scope::_findID(const ID& id, bool external) const { return _findID(this, id, external); }

void Scope::dump(std::ostream& out, const std::string& prefix) const {
    for ( const auto& [k, v] : items() ) {
        if ( v.empty() ) {
            out << util::fmt("%s%s -> <stop-lookup-here>\n", prefix, k);
            continue;
        }

        for ( const auto& x : v ) {
            if ( ! x ) {
                out << util::fmt("%s%s -> <invalid-ref>\n", prefix, k);
                continue;
            }

            auto s = util::fmt("%s%s -> %s", prefix, k, x->renderSelf(false));

            if ( x ) {
                if ( auto* d = x->tryAs<declaration::Expression>() )
                    s += util::fmt(" (type: [@e:%s] [@t:%s])", d->expression()->type()->identity(),
                                   d->expression()->type()->identity());
                else
                    s += util::fmt(" ([@d:%p])", x->identity());
            }

            out << s << '\n';
        }
    }
}

std::string Scope::print() const {
    std::stringstream ss;
    dump(ss);
    return ss.str();
}
