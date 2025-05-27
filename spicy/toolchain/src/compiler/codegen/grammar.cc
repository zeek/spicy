// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/type.h>

#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/productions/all.h>
#include <spicy/compiler/detail/codegen/productions/deferred.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;
using hilti::util::fmt;

class UnknownReference : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string Grammar::_productionLocation(const Production* p) const {
    std::string loc;

    if ( ! _name.empty() ) {
        loc += fmt("grammar %s", _name);

        if ( _location )
            loc += fmt(" (%s)", _location);

        loc += ", ";
    }

    loc += fmt("production %s", p->symbol());

    if ( p->location() )
        loc += fmt(" (%s)", p->location());

    return loc;
}

std::vector<std::vector<Production*>> Grammar::_rhss(const Production* p) {
    std::vector<std::vector<Production*>> nrhss;

    for ( const auto& rhs : p->rhss() ) {
        std::vector<Production*> nrhs;
        for ( const auto& r : rhs ) {
            if ( auto* x = r->tryAs<production::Deferred>() )
                nrhs.push_back(resolved(x)->follow());
            else
                nrhs.push_back(r->follow());
        }
        nrhss.push_back(std::move(nrhs));
    }

    return nrhss;
}

hilti::Result<hilti::Nothing> Grammar::setRoot(std::unique_ptr<Production> p) {
    if ( _root )
        return hilti::result::Error("root production is already set");

    const auto& symbol = p->symbol();

    if ( symbol.empty() )
        return hilti::result::Error("root production must have a symbol");

    _addProduction(p.get());
    _root = std::move(p);
    return hilti::Nothing();
}

void Grammar::resolve(production::Deferred* r, std::unique_ptr<Production> p) {
    _resolved_mapping[r->symbol()] = p->symbol();
    r->resolve(p.get());
    p->setMetaInstance(r->metaInstance());
    _addProduction(p.get());
    _resolved.emplace_back(std::move(p)); // retain ownership
}

Production* Grammar::resolved(const production::Deferred* r) const {
    if ( auto np = _resolved_mapping.find(r->symbol()); np != _resolved_mapping.end() )
        return _prods.at(np->second);

    throw UnknownReference(r->symbol());
}

hilti::Result<hilti::Nothing> Grammar::finalize() {
    if ( ! _root )
        return hilti::result::Error("grammar does not have a root production");

    _simplify();
    return _computeTables();
}

void Grammar::_addProduction(Production* p) {
    if ( p->symbol().empty() )
        return;

    if ( p->isA<production::Deferred>() )
        return;

    if ( _prods.find(p->symbol()) != _prods.end() )
        return;

    _prods.insert(std::make_pair(p->symbol(), p->follow()));

    if ( ! p->isTerminal() ) {
        _nterms.push_back(p->symbol());

        for ( const auto& rhs : p->rhss() )
            for ( const auto& r : rhs )
                _addProduction(r);
    }
}

void Grammar::_simplify() {
    // Remove unused productions.

    bool changed = true;

    while ( changed ) {
        changed = false;
        auto closure = _computeClosure(root());

        production::Set values;
        for ( const auto& i : _prods )
            values.insert(i.second);

        for ( const auto& p : hilti::util::setDifference(values, closure) ) {
            _prods.erase(p->symbol());
            _nterms.erase(std::remove(_nterms.begin(), _nterms.end(), p->symbol()), _nterms.end());
            changed = true;
        }
    }
}

void Grammar::_closureRecurse(production::Set* c, Production* p) {
    if ( auto* r = p->template tryAs<production::Deferred>() ) {
        assert(r->resolved());
        _closureRecurse(c, r->resolved());
        return;
    }

    if ( p->symbol().empty() || c->find(p) != c->end() )
        return;

    c->insert(p);

    if ( p->isTerminal() )
        return;

    for ( const auto& rhss : _rhss(p) )
        for ( const auto& rhs : rhss )
            _closureRecurse(c, rhs);
};

production::Set Grammar::_computeClosure(Production* p) {
    production::Set c;
    _closureRecurse(&c, p->as<Production>());
    return c;
}

bool Grammar::_add(std::map<std::string, std::set<std::string>>* tbl, Production* dst, const std::set<std::string>& src,
                   bool changed) {
    const auto& idx = dst->symbol();
    auto t = tbl->find(idx);
    assert(t != tbl->end());

    const auto& set = t->second;
    auto union_ = hilti::util::setUnion(set, src);

    if ( union_.size() == set.size() )
        // All in there already.
        return changed;

    (*tbl)[idx] = std::move(union_);
    return true;
}

bool Grammar::_isNullable(const Production* p) const {
    if ( p->isA<production::Epsilon>() )
        return true;

    if ( p->isTerminal() )
        return false;

    return _nullable.find(p->symbol())->second;
}

bool Grammar::_isNullable(std::vector<Production*>::const_iterator i,
                          std::vector<Production*>::const_iterator j) const {
    while ( i != j ) {
        auto* rhs = *i++;
        if ( ! _isNullable(rhs) )
            return false;
    }

    return true;
}

std::set<std::string> Grammar::_getFirst(const Production* p) const {
    if ( p->isA<production::Epsilon>() )
        return {};

    if ( p->isTerminal() )
        return {p->symbol()};

    return _first.find(p->symbol())->second;
}

std::set<std::string> Grammar::_getFirstOfRhs(const std::vector<Production*>& rhs) const {
    auto first = std::set<std::string>();

    for ( const auto* p : rhs ) {
        if ( p->isA<production::Epsilon>() )
            continue;

        if ( p->isTerminal() )
            return {p->symbol()};

        first = hilti::util::setUnion(first, _first.find(p->symbol())->second);

        if ( auto i = _nullable.find(p->symbol()); i == _nullable.end() )
            break;
    }

    return first;
}

hilti::Result<hilti::Nothing> Grammar::_computeTables() {
    // Computes FIRST, FOLLOW, & NULLABLE. This follows roughly the Algorithm
    // 3.13 from Modern Compiler Implementation in C by Appel/Ginsburg. See
    // http://books.google.com/books?id=A3yqQuLW5RsC&pg=PA49.

    // Initializde sets.
    for ( const auto& sym : _nterms ) {
        _nullable[sym] = false;
        _first[sym] = {};
        _follow[sym] = {};
    }

    // Iterate until no further change.
    while ( true ) {
        bool changed = false;

        for ( const auto& sym : _nterms ) {
            auto& p = _prods.find(sym)->second;

            for ( const auto& rhss : _rhss(p) ) {
                auto first = rhss.begin();
                auto last = rhss.end();

                if ( _isNullable(first, last) && ! _nullable[sym] ) {
                    _nullable[sym] = true;
                    changed = true;
                }

                for ( auto i = first; i != last; i++ ) {
                    const auto& rhs = *i;

                    if ( _isNullable(first, i) )
                        changed = _add(&_first, p, _getFirst(rhs), changed);

                    if ( rhs->isTerminal() )
                        continue;

                    auto next = i;
                    ++next;

                    if ( _isNullable(next, last) )
                        changed = _add(&_follow, rhs, _follow[sym], changed);

                    for ( auto j = next; j != last; ++j ) {
                        if ( _isNullable(next, j) ) {
                            changed = _add(&_follow, rhs, _getFirst(*j), changed);
                        }
                    }
                }
            }
        }

        if ( ! changed )
            break;
    }

    // Build the look-ahead sets.
    for ( auto& sym : _nterms ) {
        auto* p = _prods.find(sym)->second;

        if ( ! p->isA<production::LookAhead>() )
            continue;

        auto* lap = p->as<production::LookAhead>();

        auto v0 = lookAheadsForProduction(lap->alternatives().first, p);
        if ( ! v0 )
            continue;

        auto v1 = lookAheadsForProduction(lap->alternatives().second, p);
        if ( ! v1 )
            continue;

        lap->setLookAheads(std::make_pair(*v0, *v1));

        // Add v0 and v1 to the set of look-ahead tokens in use.
        for ( const auto& v : {v0, v1} ) {
            for ( const auto& x : *v )
                _look_aheads_in_use.insert(x->tokenID());
        }
    }

    return _check();
}

hilti::Result<hilti::Nothing> Grammar::_check() {
    for ( const auto& sym : _nterms ) {
        auto* lap = _prods.find(sym)->second->tryAs<production::LookAhead>();
        if ( ! lap )
            continue;

        auto laheads = lap->lookAheads();

        std::set<std::string> syms1;
        std::set<std::string> syms2;

        for ( const auto& p : laheads.first )
            syms1.insert(p->follow()->dump()); // this follow reference chains

        for ( const auto& p : laheads.second )
            syms2.insert(p->follow()->dump()); // this follow reference chains

        if ( syms1.size() == 0 && syms2.size() == 0 )
            return hilti::result::Error(
                fmt("no look-ahead symbol for either alternative in %s\n", _productionLocation(lap)));

        auto isect = hilti::util::setIntersection(syms1, syms2);

        if ( isect.size() )
            return hilti::result::Error(fmt("%s is ambiguous for look-ahead symbol(s) { %s }\n",
                                            _productionLocation(lap), hilti::util::join(isect, ", ")));

        for ( const auto& q : hilti::util::setUnion(laheads.first, laheads.second) ) {
            if ( ! q->isTerminal() )
                return hilti::result::Error(
                    fmt("%s: look-ahead cannot depend on non-terminal\n", _productionLocation(lap)));
        }
    }

    return hilti::Nothing();
}

hilti::Result<production::Set> Grammar::lookAheadsForProduction(const Production* p, const Production* parent) const {
    if ( const auto* x = p->tryAs<production::Deferred>() )
        p = resolved(x);

    auto laheads = std::set<std::string>{};

    for ( const auto& term : _getFirst(p) )
        laheads = hilti::util::setUnion(laheads, {term});

    if ( parent && _isNullable(p) ) {
        for ( const auto& term : _follow.find(parent->symbol())->second )
            laheads = hilti::util::setUnion(laheads, {term});
    }

    production::Set result;

    for ( const auto& s : laheads ) {
        auto p = _prods.find(s);
        assert(p != _prods.end());

        if ( ! p->second->isTerminal() )
            return hilti::result::Error(
                fmt("%s: look-ahead cannot depend on non-terminal", _productionLocation(p->second)));

        result.insert(p->second);
    }

    return result;
}

bool Grammar::hasLookAheadLiterals(const Production* p, const Production* parent) const {
    auto tokens = lookAheadsForProduction(p, parent);

    if ( ! tokens || tokens->empty() )
        return false;

    for ( const auto& t : *tokens ) {
        if ( t->isLiteral() )
            return true;
    }

    return false;
}

void Grammar::printTables(std::ostream& out, bool verbose) {
    Production* root = nullptr;

    if ( _root )
        root = _root->as<production::Deferred>()->resolved();

    out << "=== Grammar " << _name << '\n';

    for ( const auto& i : _prods ) {
        std::string field;

        if ( const auto& f = i.second->meta().field() ) {
            const auto* isfp = i.second->meta().isFieldProduction() ? " (*)" : "";
            field =
                fmt(" [field: %s%s] [item-type: %s] [parse-type: %s]", f->id(), isfp, *f->itemType(), *f->parseType());
        }

        out << fmt(" %3s %s%s", (root && i.first == root->symbol() ? "(*)" : ""), *i.second, field);
        if ( i.second->meta().container() )
            out << fmt(" [container: %s]", i.second->meta().container()->id());
        out << '\n';
    }

    for ( const auto& [r, p] : _resolved_mapping )
        out << fmt("     %15s: -> %s", r, p) << '\n';

    if ( ! verbose ) {
        out << '\n';
        return;
    }

    out << '\n' << "  -- Epsilon:" << '\n';

    for ( const auto& i : _nullable )
        out << fmt("     %s = %s", i.first, i.second) << '\n';

    out << '\n' << "  -- First_1:" << '\n';

    for ( const auto& i : _first )
        out << fmt("     %s = { %s }", i.first, hilti::util::join(i.second, ", ")) << '\n';

    out << '\n' << "  -- Follow:" << '\n';

    for ( const auto& i : _follow )
        out << fmt("     %s = { %s }", i.first, hilti::util::join(i.second, ", ")) << '\n';

    out << '\n';
}
