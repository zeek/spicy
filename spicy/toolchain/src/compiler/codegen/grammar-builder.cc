// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/base/cache.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/productions/all.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

using hilti::util::fmt;

namespace {

struct Visitor : public hilti::visitor::PreOrder<Production, Visitor> {
    Visitor(CodeGen* cg, codegen::GrammarBuilder* gb, Grammar* g) : cg(cg), gb(gb), grammar(g) {}
    CodeGen* cg;
    codegen::GrammarBuilder* gb;
    Grammar* grammar;

    using CurrentField = std::pair<const spicy::type::unit::item::Field&, NodeRef>;
    std::vector<CurrentField> fields;
    hilti::util::Cache<std::string, Production> cache;

    const auto& currentField() { return fields.back(); }
    void pushField(const CurrentField& f) { fields.emplace_back(f); }
    void popField() { fields.pop_back(); }
    bool haveField() { return ! fields.empty(); }

    std::optional<Production> productionForItem(const NodeRef& item) {
        auto field = item->tryAs<spicy::type::unit::item::Field>();
        if ( field )
            pushField({*field, NodeRef(item)});

        auto p = dispatch(item);

        if ( field )
            popField();

        return p;
    }

    Production productionForCtor(const Ctor& c, const ID& id) {
        return production::Ctor(cg->uniquer()->get(id), c, c.meta().location());
    }

    Production productionForType(const Type& t, const ID& id) {
        if ( auto prod = dispatch(t) )
            return std::move(*prod);

        // Fallback: Just a plain type.
        return production::Variable(cg->uniquer()->get(id), t, t.meta().location());
    }

    Production productionForLoop(Production sub, position_t p) {
        const auto& loc = p.node.location();
        const auto& field = currentField().first;
        auto id = cg->uniquer()->get(field.id());
        auto eod = AttributeSet::find(field.attributes(), "&eod");
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
            return production::Counter(id, *count->valueAsExpression(), sub, loc);

        if ( size )
            // When parsing, our view will be limited to the specified input
            // size, so just iterate until EOD.
            return production::ForEach(id, sub, true, loc);

        if ( parse_at || parse_from )
            // Custom input, just iterate until EOD.
            return production::ForEach(id, sub, true, loc);

        if ( while_ || until || until_including || eod )
            // The container parsing will evaluate the corresponding stop
            // condition as necessary.
            return production::ForEach(id, sub, true, loc);

        // Nothing specified, use look-ahead to figure out when to stop
        // parsing.
        auto c = production::While(id, std::move(sub), loc);
        c.preprocessLookAhead(grammar);
        auto me = c.meta();
        me.setField(NodeRef(currentField().second), false);
        c.setMeta(std::move(me));
        return std::move(c);
    }

    Production operator()(const spicy::type::unit::item::Field& n, position_t p) {
        if ( n.isSkip() ) {
            // For field types that support it, create a dedicated skip production.
            std::optional<Production> skip;

            if ( const auto& ctor = n.ctor() ) {
                auto prod = productionForCtor(*ctor, n.id());
                auto m = prod.meta();
                m.setField(NodeRef(currentField().second), true);
                prod.setMeta(std::move(m));
                skip = production::Skip(cg->uniquer()->get(n.id()), NodeRef(p.node), prod, n.meta().location());
            }

            else if ( n.item() ) {
                // Skipping not supported
            }

            else if ( n.parseType().isA<type::Bytes>() ) {
                auto eod_attr = AttributeSet::find(n.attributes(), "&eod");
                auto size_attr = AttributeSet::find(n.attributes(), "&size");
                auto until_attr = AttributeSet::find(n.attributes(), "&until");
                auto until_including_attr = AttributeSet::find(n.attributes(), "&until-including");

                if ( eod_attr || size_attr || until_attr || until_including_attr )
                    skip = production::Skip(cg->uniquer()->get(n.id()), NodeRef(p.node), {}, n.meta().location());
            }

            if ( n.repeatCount() )
                skip.reset();

            auto convert_attr = AttributeSet::find(n.attributes(), "&convert");
            auto requires_attr = AttributeSet::find(n.attributes(), "&requires");
            if ( convert_attr || requires_attr )
                skip.reset();

            if ( skip )
                return std::move(*skip);
        }

        Production prod;

        if ( const auto& c = n.ctor() ) {
            prod = productionForCtor(*c, n.id());

            if ( n.isContainer() )
                prod = productionForLoop(prod, p);
        }
        else if ( n.item() ) {
            auto sub = productionForItem(p.node.as<spicy::type::unit::item::Field>().itemRef());
            auto m = sub->meta();

            if ( n.isContainer() )
                prod = productionForLoop(std::move(*sub), p);
            else {
                if ( sub->meta().field() ) {
                    auto field = sub->meta().fieldRef();
                    const_cast<type::unit::item::Field&>(field->as<type::unit::item::Field>()).setForwarding(true);
                }

                prod = production::Enclosure(cg->uniquer()->get(n.id()), *sub);
            }
        }
        else
            prod = productionForType(n.parseType(), n.id());

        auto m = prod.meta();
        m.setField(NodeRef(currentField().second), true);
        prod.setMeta(std::move(m));

        return prod;
    }

    Production operator()(const spicy::type::unit::item::Switch& n, position_t p) {
        auto productionForCase = [this](const spicy::type::unit::item::switch_::Case& c, const std::string& label) {
            std::vector<Production> prods;

            for ( const auto& n : c.itemRefs() ) {
                if ( auto prod = productionForItem(NodeRef(n)) )
                    prods.push_back(*prod);
            }

            return production::Sequence(label, std::move(prods), c.meta().location());
        };

        auto switch_sym = cg->uniquer()->get("switch");

        if ( n.expression() ) {
            // Switch based on value of expression.
            production::Switch::Cases cases;
            std::optional<Production> default_;
            int i = 0;

            for ( const auto& c : p.node.as<spicy::type::unit::item::Switch>().cases() ) {
                if ( c.isDefault() )
                    default_ = productionForCase(c, fmt("%s_default", switch_sym));
                else {
                    auto prod = productionForCase(c, fmt("%s_case_%d", switch_sym, ++i));
                    cases.emplace_back(c.expressions().copy(), std::move(prod));
                }
            }

            AttributeSet attributes;
            if ( auto a = n.attributes() )
                attributes = *a;

            return production::Switch(switch_sym, *n.expression(), std::move(cases), std::move(default_),
                                      std::move(attributes), n.meta().location());
        }

        else {
            // Switch by look-ahead.
            std::optional<Production> prev;

            int i = 0;
            auto d = production::look_ahead::Default::None;

            for ( const auto& c : p.node.as<spicy::type::unit::item::Switch>().cases() ) {
                Production prod;

                if ( c.isDefault() )
                    prod = productionForCase(c, fmt("%s_default", switch_sym));
                else
                    prod = productionForCase(c, fmt("%s_case_%d", switch_sym, ++i));

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
            *n.id(), []() { return production::Unresolved(); },
            [&](auto& unresolved) {
                auto id = cg->uniquer()->get(*n.id());

                std::vector<Production> items;

                for ( const auto& n : p.node.as<type::Unit>().childRefsOfType<spicy::type::unit::Item>() ) {
                    if ( auto p = productionForItem(NodeRef(n)) )
                        items.push_back(*p);
                }

                hilti::node::Range<Expression> args;

                if ( haveField() )
                    args = currentField().first.arguments();

                auto unit = production::Unit(id, n, args.copy(), std::move(items), n.meta().location());
                grammar->resolve(&unresolved.template as<production::Unresolved>(), std::move(unit));
                return unresolved;
            });

        // Give this production its own meta instance. Due to the caching it
        // would normally have a shared one.
        // TODO(robin): Rename _setMetaInstance(), or give it clearMeta() or such.
        prod._setMetaInstance(std::make_shared<production::Meta>());
        return prod;
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

Result<Nothing> GrammarBuilder::run(const type::Unit& unit, Node* node, CodeGen* cg) {
    assert(unit.id());
    const auto& id = *unit.id();
    Grammar g(id, node->location());
    auto v = Visitor(cg, this, &g);

    auto root = v.dispatch(node);
    assert(root);

    g.setRoot(*root);

    auto r = g.finalize();

    if ( hilti::logger().isEnabled(spicy::logging::debug::Grammar) ) {
        hilti::logging::Stream dbg(spicy::logging::debug::Grammar);
        g.printTables(dbg, true);
    }

    if ( ! r )
        return r.error();

    _grammars[id] = std::move(g);
    return Nothing();
}

const Grammar& GrammarBuilder::grammar(const type::Unit& unit) {
    if ( _grammars.find(*unit.id()) == _grammars.end() )
        hilti::logger().internalError(fmt("grammar for unit %s accessed before it's been computed", *unit.id()),
                                      unit.meta().location());

    return _grammars[*unit.id()];
}
