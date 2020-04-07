// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/type.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/productions/all.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;
using util::fmt;

class UnknownReference : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::string Grammar::_productionLocation(const Production& p) const {
    std::string loc;

    if ( ! _name.empty() ) {
        loc += fmt("grammar %s", _name);

        if ( _location )
            loc += fmt(" (%s)", _location);

        loc += ", ";
    }

    loc += fmt("production %s", p.symbol());

    if ( p.location() )
        loc += fmt(" (%s)", p.location());

    return loc;
}

std::vector<std::vector<Production>> Grammar::_rhss(const Production& p) {
    std::vector<std::vector<Production>> nrhss;

    for ( const auto& rhs : p.rhss() ) {
        std::vector<Production> nrhs;
        for ( const auto& r : rhs ) {
            if ( auto x = r.tryAs<production::Resolved>() )
                nrhs.push_back(resolved(*x));
            else
                nrhs.push_back(r);
        }
        nrhss.push_back(std::move(nrhs));
    }

    return nrhss;
}

Result<Nothing> Grammar::setRoot(const Production& p) {
    if ( _root )
        return hilti::result::Error("root production is already set");

    auto symbol = p.symbol();

    if ( symbol.empty() )
        return hilti::result::Error("root production must have a symbol");

    _addProduction(p);
    _root = std::move(symbol);
    return Nothing();
}

void Grammar::resolve(production::Unresolved* r, Production p) {
    _resolved[r->referencedSymbol()] = p.symbol();
    r->resolve(p.symbol());
    p._setMetaInstance(r->_metaInstance());
    _addProduction(p);
}

const Production& Grammar::resolved(const production::Resolved& r) const {
    if ( auto np = _resolved.find(r.referencedSymbol()); np != _resolved.end() )
        return _prods.at(np->second);

    throw UnknownReference(r.referencedSymbol());
}

Result<Nothing> Grammar::finalize() {
    if ( ! _root )
        return hilti::result::Error("grammar does not have a root production");

    _simplify();
    return _computeTables();
}

void Grammar::_addProduction(const Production& p) {
    if ( p.symbol().empty() )
        return;

    if ( p.isA<production::Resolved>() )
        return;

    if ( _prods.find(p.symbol()) != _prods.end() )
        return;

    _prods.insert(std::make_pair(p.symbol(), p));

    if ( p.isNonTerminal() ) {
        _nterms.push_back(p.symbol());

        for ( const auto& rhs : p.rhss() )
            for ( const auto& r : rhs )
                _addProduction(r);
    }

    if ( p.isA<production::LookAhead>() || p.isLiteral() )
        _needs_look_ahead = true;
}

void Grammar::_simplify() {
    // Remove unused productions.

    bool changed = true;

    while ( changed ) {
        changed = false;
        auto closure = _computeClosure(*root());

        for ( const auto& p : util::set_difference(util::map_values(_prods), closure) ) {
            _prods.erase(p.symbol());
            _nterms.erase(std::remove(_nterms.begin(), _nterms.end(), p.symbol()), _nterms.end());
            changed = true;
        }
    }
}

std::set<Production> Grammar::_computeClosure(const Production& p) {
    std::function<void(std::set<Production>&, const Production&)> closure = [&](auto& c, const auto& p) -> void {
        if ( p.symbol().empty() || c.find(p) != c.end() )
            return;

        c.insert(p);

        if ( p.isTerminal() )
            return;

        for ( const auto& rhss : _rhss(p) )
            for ( const auto& rhs : rhss )
                closure(c, rhs);
    };

    std::set<Production> c;
    closure(c, p);
    return c;
}

bool Grammar::_add(std::map<std::string, std::set<std::string>>* tbl, const Production& dst,
                   const std::set<std::string>& src, bool changed) {
    const auto& idx = dst.symbol();
    auto t = tbl->find(idx);
    assert(t != tbl->end());

    auto set = t->second;
    auto union_ = util::set_union(set, src);

    if ( union_.size() == set.size() )
        // All in there already.
        return changed;

    (*tbl)[idx] = union_;
    return true;
}

bool Grammar::_isNullable(std::vector<Production>::const_iterator i, std::vector<Production>::const_iterator j) {
    while ( i != j ) {
        auto rhs = *i++;

        if ( rhs.isA<production::Epsilon>() )
            continue;

        if ( rhs.isTerminal() )
            return false;

        if ( ! _nullable[rhs.symbol()] )
            return false;
    }

    return true;
}

std::set<std::string> Grammar::_getFirst(const Production& p) {
    if ( p.isA<production::Epsilon>() )
        return {};

    if ( p.isTerminal() )
        return {p.symbol()};

    return _first[p.symbol()];
}

std::set<std::string> Grammar::_getFirstOfRhs(const std::vector<Production>& rhs) {
    auto first = std::set<std::string>();

    for ( const auto& p : rhs ) {
        if ( p.isA<production::Epsilon>() )
            continue;

        if ( p.isTerminal() )
            return {p.symbol()};

        first = util::set_union(first, _first[p.symbol()]);

        if ( ! _nullable[p.symbol()] )
            break;
    }

    return first;
}

Result<Nothing> Grammar::_computeTables() {
    // Computes FIRST, FOLLOW, & NULLABLE. This follows roughly the Algorithm
    // 3.13 from Modern Compiler Implementation in C by Appel/Ginsburg. See
    // http://books.google.com/books?id=A3yqQuLW5RsC&pg=PA49.

    // Initializde sets.
    for ( const auto& sym : _nterms ) {
        _nullable[sym] = false;
        _first[sym] = {};
        _follow[sym] = {};
    }

    // SafeIterator until no further change.
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
                    auto rhs = *i;

                    if ( _isNullable(first, i) )
                        changed = _add(&_first, p, _getFirst(rhs), changed);

                    if ( ! rhs.isNonTerminal() )
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
        auto& p = _prods.find(sym)->second;

        if ( ! p.isA<production::LookAhead>() )
            continue;

        auto& lap = p.as<production::LookAhead>();
        auto rhss = _rhss(p);

        assert(rhss.size() == 2);
        auto r = rhss.begin();

        auto laheads = std::vector<std::set<std::string>>{{}, {}};

        for ( auto i = 0; i < 2; ++i ) {
            auto rhs = *r++;

            for ( const auto& term : _getFirstOfRhs(rhs) )
                laheads[i] = util::set_union(laheads[i], {term});

            if ( _isNullable(rhs.begin(), rhs.end()) ) {
                for ( const auto& term : _follow[sym] )
                    laheads[i] = util::set_union(laheads[i], {term});
            }
        }

        std::set<Production> v0;
        std::set<Production> v1;
        std::set<std::string> lahs;

        for ( auto i = 0; i < 2; ++i ) {
            for ( const auto& s : laheads[i] ) {
                auto p = _prods.find(s);
                assert(p != _prods.end());

                if ( p->second.isNonTerminal() )
                    return hilti::result::Error(
                        fmt("%s: look-ahead cannot depend on non-terminal", _productionLocation(p->second)));

                if ( i == 0 )
                    v0.insert(p->second);
                else
                    v1.insert(p->second);
            }
        }

        lap.setLookAheads(std::make_pair(std::move(v0), std::move(v1)));
    }

    return _check();
}

Result<Nothing> Grammar::_check() {
    for ( const auto& sym : _nterms ) {
        auto& p = _prods.find(sym)->second;

        if ( ! p.isA<production::LookAhead>() )
            continue;

        auto& lap = _prods.find(sym)->second.as<production::LookAhead>();
        auto laheads = lap.lookAheads();

        std::set<std::string> syms1;
        std::set<std::string> syms2;

        for ( const auto& p : laheads.first )
            syms1.insert(p.render());

        for ( const auto& p : laheads.second )
            syms2.insert(p.render());

        if ( syms1.size() == 0 && syms2.size() == 0 )
            return hilti::result::Error(
                fmt("no look-ahead symbol for either alternative in %s\n", _productionLocation(p)));

        auto isect = util::set_intersection(syms1, syms2);

        if ( isect.size() )
            return hilti::result::Error(fmt("%s is ambigious for look-ahead symbol(s) { %s }\n", _productionLocation(p),
                                            util::join(isect, ", ")));

        for ( const auto& q : util::set_union(laheads.first, laheads.second) ) {
            if ( ! q.isTerminal() )
                return hilti::result::Error(
                    fmt("%s: look-ahead cannot depend on non-terminal\n", _productionLocation(p)));
        }
    }

    return Nothing();
}

void Grammar::printTables(std::ostream& out, bool verbose) {
    out << "=== Grammar " << _name << std::endl;

    for ( const auto& i : _prods ) {
        std::string field;

        if ( const auto& f = i.second.meta().field() ) {
            auto isfp = i.second.meta().isFieldProduction() ? " (*)" : "";
            field =
                fmt(" [field: %s%s] [item-type: %s] [parse-type: %s]", f->id(), isfp, f->itemType(), f->parseType());
        }

        out << fmt(" %3s %s%s", (_root && i.first == _root ? "(*)" : ""), i.second, field) << std::endl;
    }

    if ( ! verbose ) {
        out << std::endl;
        return;
    }

    out << std::endl << "  -- Epsilon:" << std::endl;

    for ( const auto& i : _nullable )
        out << fmt("     %s = %s", i.first, i.second) << std::endl;

    out << std::endl << "  -- First_1:" << std::endl;

    for ( const auto& i : _first )
        out << fmt("     %s = { %s }", i.first, util::join(i.second, ", ")) << std::endl;

    out << std::endl << "  -- Follow:" << std::endl;

    for ( const auto& i : _follow )
        out << fmt("     %s = { %s }", i.first, util::join(i.second, ", ")) << std::endl;

    out << std::endl;
}
