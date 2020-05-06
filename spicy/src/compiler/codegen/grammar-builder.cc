// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/base/cache.h>
#include <hilti/base/uniquer.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/productions/all.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

using util::fmt;

namespace {

struct Visitor : public hilti::visitor::PreOrder<Production, Visitor> {
    Visitor(codegen::GrammarBuilder* gb, Grammar* g) : gb(gb), grammar(g) {}
    codegen::GrammarBuilder* gb;
    Grammar* grammar;

    using CurrentField = std::pair<const spicy::type::unit::item::Field&, std::reference_wrapper<hilti::Node>&>;
    std::vector<CurrentField> fields;
    util::Cache<std::string, Production> cache;
    util::Uniquer<std::string> uniquer;

    auto currentField() { return fields.back(); }

    void pushField(CurrentField f) { fields.emplace_back(f); }

    void popField() { fields.pop_back(); }

    bool haveField() { return ! fields.empty(); }

    std::optional<Production> productionForItem(std::reference_wrapper<hilti::Node> node) {
        auto field = node.get().tryAs<const spicy::type::unit::item::Field>();
        if ( field )
            pushField({*field, node});

        auto p = dispatch(node);

        if ( field )
            popField();

        return p;
    }

    Production productionForCtor(const Ctor& c, const ID& id) {
        return production::Ctor(uniquer.get(id), c, c.meta().location());
    }

    Production productionForType(const Type& t, const ID& id) {
        if ( auto prod = dispatch(hilti::type::effectiveType(t)) )
            return std::move(*prod);

        // Fallback: Just a plain type.
        return production::Variable(uniquer.get(id), t, t.meta().location());
    }

    Production productionForLoop(Production sub, position_t p) {
        const auto& loc = p.node.location();
        auto& field = currentField().first;
        auto id = uniquer.get(field.id());
        auto count = AttributeSet::find(field.attributes(), "&count");
        auto size = AttributeSet::find(field.attributes(), "&size");
        auto parse_at = AttributeSet::find(field.attributes(), "&parse-at");
        auto parse_from = AttributeSet::find(field.attributes(), "&parse-from");
        auto until = AttributeSet::find(field.attributes(), "&until");
        auto until_including = AttributeSet::find(field.attributes(), "&until-including");
        auto while_ = AttributeSet::find(field.attributes(), "&while");
        auto repeat = field.repeatCount();

        auto m = sub.meta();

        if ( ! m.field() )
            m.setField(NodeRef(currentField().second), false);

        m.setContainer(NodeRef(currentField().second));
        sub.setMeta(std::move(m));

        if ( repeat && ! repeat->type().isA<type::Null>() )
            return production::Counter(id, *repeat, sub, loc);

        if ( count )
            return production::Counter(id, *count->valueAs<Expression>(), sub, loc);

        if ( size )
            // When parsing, our view will be limited to the specified input
            // size, so just iterate until EOD.
            return production::ForEach(id, sub, true, loc);

        if ( parse_at || parse_from )
            // Custom input, just iterate until EOD.
            return production::ForEach(id, sub, true, loc);

        if ( while_ || until || until_including )
            // The container parsing will evaluate the corresponding stop
            // conditon.
            return production::ForEach(id, sub, true, loc);

        // Nothing specified, use look-ahead to figure out when to stop
        // parsing.
        //
        // Left-factored & right-recursive.
        //
        // List1 -> Item List2
        // List2 -> Epsilon | List1

        auto x = production::Unresolved();
        auto l1 = production::LookAhead(id + "_l1", production::Epsilon(loc), x, loc);
        auto l2 = production::Sequence(id + "_l2", {sub, l1}, loc);
        grammar->resolve(&x, std::move(l2));

        auto c = production::Enclosure(id, std::move(l1), loc);
        auto me = c.meta();
        me.setField(NodeRef(currentField().second), false);
        c.setMeta(std::move(me));
        return std::move(c);
    }

    Production operator()(const spicy::type::unit::item::Field& n, position_t p) {
        Production prod;

        if ( auto c = n.ctor() ) {
            prod = productionForCtor(*c, n.id());

            if ( n.itemType().isA<type::Vector>() || n.itemType().isA<type::List>() )
                prod = productionForLoop(prod, p);
        }
        else if ( n.vectorItem() ) {
            auto sub = productionForItem(p.node.as<spicy::type::unit::item::Field>().vectorItemNode());
            assert(sub);
            prod = productionForLoop(std::move(*sub), p);
        }
        else
            prod = productionForType(n.parseType(), n.id());

        auto m = prod.meta();
        m.setField(NodeRef(currentField().second), true);
        prod.setMeta(std::move(m));
        return prod;
    }

    Production operator()(const spicy::type::unit::item::Switch& n, position_t p) {
        auto productionForCase = [this](Node& c, const std::string& label) {
            std::vector<Production> prods;

            for ( auto&& n : c.as<spicy::type::unit::item::switch_::Case>().itemNodes() ) {
                if ( auto prod = productionForItem(n) )
                    prods.push_back(*prod);
            }

            return production::Sequence(label, std::move(prods), c.meta().location());
        };

        auto switch_sym = uniquer.get("switch");

        if ( n.expression() ) {
            // Switch based on value of expression.
            production::Switch::Cases cases;
            std::optional<Production> default_;
            int i = 0;

            for ( auto&& n : p.node.as<spicy::type::unit::item::Switch>().casesNodes() ) {
                auto c = n.get().as<spicy::type::unit::item::switch_::Case>();

                if ( c.isDefault() )
                    default_ = productionForCase(n, fmt("%s_default", switch_sym));
                else {
                    auto prod = productionForCase(n, fmt("%s_case_%d", switch_sym, ++i));
                    cases.emplace_back(c.expressions(), std::move(prod));
                }
            }

            return production::Switch(switch_sym, *n.expression(), std::move(cases), std::move(default_),
                                      n.meta().location());
        }

        else {
            // Switch by look-ahead.
            std::optional<Production> prev;

            int i = 0;
            auto d = production::look_ahead::Default::None;

            for ( auto&& n : p.node.as<spicy::type::unit::item::Switch>().casesNodes() ) {
                auto c = n.get().as<spicy::type::unit::item::switch_::Case>();

                Production prod;

                if ( c.isDefault() )
                    prod = productionForCase(n, fmt("%s_default", switch_sym));
                else
                    prod = productionForCase(n, fmt("%s_case_%d", switch_sym, ++i));

                if ( ! prev ) {
                    prev = prod;

                    if ( c.isDefault() )
                        d = production::look_ahead::Default::First;

                    continue;
                }

                if ( c.isDefault() )
                    d = production::look_ahead::Default::Second;

                auto lah_sym = fmt("%s_lha_%d", switch_sym, i);
                auto lah = production::LookAhead(lah_sym, std::move(*prev), std::move(prod), d, c.meta().location());
                prev = std::move(lah);
            }

            return *prev;
        }
    }

    Production operator()(const hilti::declaration::Type& t) { return *dispatch(t.type()); }

    Production operator()(const type::Unit& n, position_t p) {
        auto prod = cache.getOrCreate(
            *n.typeID(), []() { return production::Unresolved(); },
            [&](auto& unresolved) {
                auto id = uniquer.get(*n.typeID());

                std::vector<Production> items;

                for ( auto n : p.node.as<type::Unit>().nodesOfType<spicy::type::unit::Item>() ) {
                    if ( auto p = productionForItem(n) )
                        items.push_back(*p);
                }

                std::vector<Expression> args;

                if ( haveField() )
                    args = currentField().first.arguments();

                auto unit = production::Unit(id, n, std::move(args), std::move(items), n.meta().location());
                grammar->resolve(&unresolved.template as<production::Unresolved>(), std::move(unit));
                return unresolved;
            });

        // Give this production its own meta instance. Due to the caching it
        // would normally have a shared one.
        // TODO(robin): Rename _setMetaInstance(), or give it clearMeta() or such.
        prod._setMetaInstance(std::make_shared<production::Meta>());
        return prod;
    }

    Production operator()(const type::ResolvedID& n) {
        auto t = (*n.ref()).as<hilti::declaration::Type>().type();
        auto x = dispatch(t);
        assert(x);
        return *x;
    }

    Production operator()(const type::Struct& n, position_t /* p */) {
        // Must be a unit that's already been converted.
        assert(n.originalNode());
        auto x = dispatch(*n.originalNode());
        return *x;
    }

    Production operator()(const type::ValueReference& n, position_t /* p */) {
        // Forward to referenced type, which will usually be a unit.
        auto x = dispatch(n.dereferencedType());
        assert(x);
        return *x;
    }

    Production operator()(const type::Vector& n, position_t p) {
        auto sub = productionForType(n.elementType(), ID(fmt("%s", n.elementType())));
        return productionForLoop(std::move(sub), p);
    }
};

} // anonymous namespace

Result<Nothing> GrammarBuilder::run(const type::Unit& unit, Node* node) {
    assert(unit.typeID());
    auto id = *unit.typeID();
    Grammar g(id, node->location());
    auto v = Visitor(this, &g);

    auto root = v.dispatch(node);
    assert(root);

    g.setRoot(*root);

    if ( auto r = g.finalize(); ! r )
        return r.error();

    if ( hilti::logger().isEnabled(spicy::logging::debug::Grammar) ) {
        hilti::logging::Stream dbg(spicy::logging::debug::Grammar);
        g.printTables(dbg, true);
    }

    _grammars[id] = std::move(g);
    return Nothing();
}

const Grammar& GrammarBuilder::grammar(const type::Unit& unit) {
    if ( _grammars.find(*unit.typeID()) == _grammars.end() )
        hilti::logger().internalError(fmt("grammar for unit %s accessed before it's been computed", *unit.typeID()),
                                      unit.meta().location());

    return _grammars[*unit.typeID()];
}
