// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/base/cache.h>

#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/codegen/codegen.h>
#include <spicy/compiler/detail/codegen/grammar-builder.h>
#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/productions/all.h>

using namespace spicy;
using namespace spicy::detail;
using namespace spicy::detail::codegen;

using hilti::util::fmt;

namespace {

struct ProductionFactory {
    ProductionFactory(CodeGen* cg, codegen::GrammarBuilder* gb, Grammar* g) : cg(cg), grammar(g) {}

    const auto& currentField() { return fields.back(); }
    void pushField(spicy::type::unit::item::Field* f) { fields.emplace_back(f); }
    void popField() { fields.pop_back(); }
    bool haveField() { return ! fields.empty(); }

    std::unique_ptr<Production> createProduction(Node* node);

    std::vector<spicy::type::unit::item::Field*> fields;
    hilti::util::Cache<ID, Production*> cache;
    CodeGen* cg;
    Grammar* grammar;
};

struct Visitor : public visitor::PreOrder {
    Visitor(ProductionFactory* pf) : pf(pf) {}

    ProductionFactory* pf;

    std::unique_ptr<Production> result;

    auto context() const { return pf->cg->context(); }

    std::unique_ptr<Production> productionForItem(Node* item) {
        auto field = item->tryAs<spicy::type::unit::item::Field>();
        if ( field )
            pf->pushField(field);

        auto p = pf->createProduction(item);

        if ( field )
            pf->popField();

        return p;
    }

    std::unique_ptr<Production> productionForCtor(Ctor* c, const ID& id) {
        return std::make_unique<production::Ctor>(context(), pf->cg->uniquer()->get(id), c, c->meta().location());
    }

    std::unique_ptr<Production> productionForType(QualifiedType* t, const ID& id) {
        if ( auto prod = pf->createProduction(t->type()) )
            return prod;
        else
            // Fallback: Just a plain type.
            return std::make_unique<production::Variable>(context(), pf->cg->uniquer()->get(id, false), t,
                                                          t->meta().location());
    }

    std::unique_ptr<Production> productionForLoop(std::unique_ptr<Production> sub, Node* n) {
        const auto& loc = n->location();
        const auto& field = pf->currentField();
        auto id = pf->cg->uniquer()->get(field->id());
        auto eod = field->attributes()->find("&eod");
        auto count = field->attributes()->find("&count");
        auto size = field->attributes()->find("&size");
        auto parse_at = field->attributes()->find("&parse-at");
        auto parse_from = field->attributes()->find("&parse-from");
        auto until = field->attributes()->find("&until");
        auto until_including = field->attributes()->find("&until-including");
        auto while_ = field->attributes()->find("&while");
        auto repeat = field->repeatCount();

        auto m = sub->meta();

        if ( ! m.field() )
            m.setField(field, false);

        m.setContainer(field);
        sub->setMeta(m);

        if ( repeat && ! repeat->type()->type()->isA<hilti::type::Null>() )
            return std::make_unique<production::Counter>(context(), id, repeat, std::move(sub), loc);

        if ( count )
            return std::make_unique<production::Counter>(context(), id, *count->valueAsExpression(), std::move(sub),
                                                         loc);

        if ( size )
            // When parsing, our view will be limited to the specified input size, so just iterate until EOD.
            return std::make_unique<production::ForEach>(context(), id, std::move(sub), true, loc);

        if ( parse_at || parse_from )
            // Custom input, just iterate until EOD.
            return std::make_unique<production::ForEach>(context(), id, std::move(sub), true, loc);

        if ( while_ || until || until_including || eod )
            // The container parsing will evaluate the corresponding stop
            // condition as necessary.
            return std::make_unique<production::ForEach>(context(), id, std::move(sub), true, loc);

        // Nothing specified, use look-ahead to figure out when to stop
        // parsing.
        auto c = std::make_unique<production::While>(id, std::move(sub), loc);
        c->preprocessLookAhead(pf->cg->context(), pf->grammar);
        auto me = c->meta();
        me.setField(field, false);
        c->setMeta(me);
        return std::move(c);
    }

    void operator()(spicy::type::unit::item::Block* n) final {
        std::vector<std::unique_ptr<Production>> prods;

        for ( const auto& n : n->items() ) {
            if ( auto prod = productionForItem(n) )
                prods.push_back(std::move(prod));
        }

        std::vector<std::unique_ptr<Production>> else_prods;
        for ( const auto& n : n->elseItems() ) {
            if ( auto prod = productionForItem(n) )
                else_prods.push_back(std::move(prod));
        }

        auto block_label = pf->cg->uniquer()->get("block");
        result = std::make_unique<production::Block>(context(), block_label, std::move(prods), n->condition(),
                                                     std::move(else_prods), n->attributes(), n->meta().location());
    }

    void operator()(spicy::type::unit::item::Field* n) final {
        if ( n->isSkip() ) {
            // For field types that support it, create a dedicated skip production.
            std::unique_ptr<Production> skip;

            if ( const auto& ctor = n->ctor() ) {
                auto prod = productionForCtor(ctor, n->id());
                auto m = prod->meta();
                m.setField(pf->currentField(), false);
                prod->setMeta(m);
                skip = std::make_unique<production::Skip>(context(), pf->cg->uniquer()->get(n->id()), n,
                                                          std::move(prod), n->meta().location());
            }

            else if ( n->item() ) {
                // Skipping not supported
            }

            else if ( n->size(context()) )
                skip = std::make_unique<production::Skip>(context(), pf->cg->uniquer()->get(n->id()), n, nullptr,
                                                          n->meta().location());

            else if ( n->parseType()->type()->isA<hilti::type::Bytes>() ) {
                // Bytes with fixed size already handled above.
                auto eod_attr = n->attributes()->find("&eod");
                auto until_attr = n->attributes()->find("&until");
                auto until_including_attr = n->attributes()->find("&until-including");

                if ( eod_attr || until_attr || until_including_attr )
                    skip = std::make_unique<production::Skip>(context(), pf->cg->uniquer()->get(n->id()), n, nullptr,
                                                              n->meta().location());
            }

            if ( n->repeatCount() )
                skip.reset();

            auto convert_attr = n->attributes()->find("&convert");
            auto requires_attr = n->attributes()->find("&requires");
            if ( convert_attr || requires_attr )
                skip.reset();

            if ( skip ) {
                result = std::move(skip);
                return;
            }
        }

        std::unique_ptr<Production> prod;

        if ( auto c = n->ctor() ) {
            prod = productionForCtor(c, n->id());

            if ( n->isContainer() )
                prod = productionForLoop(std::move(prod), n);
        }
        else if ( n->item() ) {
            auto sub = productionForItem(n->item());

            if ( n->isContainer() )
                prod = productionForLoop(std::move(sub), n);
            else {
                if ( sub->meta().field() )
                    sub->meta().field()->setForwarding(true);

                prod =
                    std::make_unique<production::Enclosure>(context(), pf->cg->uniquer()->get(n->id()), std::move(sub));
            }
        }
        else
            prod = productionForType(n->parseType(), n->id());

        auto m = prod->meta();
        m.setField(pf->currentField(), true);
        prod->setMeta(m);

        result = std::move(prod);
    }

    void operator()(spicy::type::unit::item::Switch* n) final {
        auto switch_sym = pf->cg->uniquer()->get("switch");

        if ( n->expression() ) {
            // Switch based on value of expression.
            production::Switch::Cases cases;
            std::unique_ptr<Production> default_;
            int i = 0;

            for ( const auto& c : n->cases() ) {
                if ( c->isDefault() ) {
                    default_ = productionForItem(c->block());
                    default_->setSymbol(fmt("%s_default", switch_sym)); // set more descriptive symbol name
                }
                else {
                    auto prod = productionForItem(c->block());
                    prod->setSymbol(fmt("%s_case_%d", switch_sym, ++i)); // set more descriptive symbol name
                    cases.emplace_back(c->expressions(), std::move(prod));
                }
            }

            result = std::make_unique<production::Switch>(context(), switch_sym, n->expression(), std::move(cases),
                                                          std::move(default_), n->attributes(), n->condition(),
                                                          n->meta().location());
            return;
        }

        else {
            // Switch by look-ahead.
            std::unique_ptr<Production> prev;

            int i = 0;
            auto d = production::look_ahead::Default::None;

            for ( const auto& c : n->cases() ) {
                auto prod = productionForItem(c->block());

                if ( prod ) {
                    // Set more descriptive symbol names for the case productions.
                    if ( c->isDefault() )
                        prod->setSymbol(fmt("%s_default", switch_sym));
                    else
                        prod->setSymbol(fmt("%s_case_%d", switch_sym, ++i));
                }

                if ( ! prev ) {
                    prev = std::move(prod);

                    if ( c->isDefault() )
                        d = production::look_ahead::Default::First;

                    continue;
                }

                if ( c->isDefault() )
                    d = production::look_ahead::Default::Second;

                auto lah_sym = fmt("%s_lha_%d", switch_sym, i);
                auto lah = std::make_unique<production::LookAhead>(context(), lah_sym, std::move(prev), std::move(prod),
                                                                   d, n->condition(), c->meta().location());
                prev = std::move(lah);
            }

            result = std::move(prev);
            return;
        }
    }

    void operator()(hilti::declaration::Type* n) final { result = pf->createProduction(n->type()); }

    void operator()(type::Unit* n) final {
        // Note: We can't use the cache's getOrCreate() here because of the
        // unique_ptr storage semantics.
        auto id = n->canonicalID();
        assert(id);

        if ( auto p = pf->cache.get(id) ) {
            auto r = dynamic_cast<production::Deferred*>(*p);
            assert(r);
            result = std::make_unique<production::Reference>(context(), r);
            return;
        }

        // Prime the cache for any self-recursive unit productions.
        auto unresolved = std::make_unique<production::Deferred>(context(), n->location());
        pf->cache.put(id, unresolved.get());

        // Now compute the actual production.
        auto pid = pf->cg->uniquer()->get(id);

        std::vector<std::unique_ptr<Production>> items;

        for ( const auto& n : n->childrenOfType<spicy::type::unit::Item>() ) {
            if ( auto p = productionForItem(n) )
                items.push_back(std::move(p));
        }

        Expressions args;

        if ( pf->haveField() )
            args = pf->currentField()->arguments();

        auto unit = std::make_unique<production::Unit>(context(), pid, n, args, std::move(items), n->meta().location());

        // This takes ownership of the unit production, storing it inside the grammar.
        pf->grammar->resolve(dynamic_cast<production::Deferred*>(unresolved.get()), std::move(unit));

        result = std::move(unresolved);
    }

    void operator()(hilti::type::Vector* n) final {
        auto sub = productionForType(n->elementType(), ID(fmt("%s", *n->elementType())));
        result = productionForLoop(std::move(sub), n);
    }
};

std::unique_ptr<Production> ProductionFactory::createProduction(Node* node) {
    return visitor::dispatch(Visitor(this), node,
                             [](auto& v) -> std::unique_ptr<Production> { return std::move(v.result); });
}

} // anonymous namespace

hilti::Result<hilti::Nothing> GrammarBuilder::run(type::Unit* unit) {
    assert(unit->canonicalID());
    auto id = unit->canonicalID();
    if ( _grammars.find(id) != _grammars.end() )
        return hilti::Nothing();

    Grammar g(id.str(), unit->location());
    auto pf = ProductionFactory(cg(), this, &g);
    auto root = pf.createProduction(unit);
    assert(root);

    if ( auto rc = g.setRoot(std::move(root)); ! rc )
        return rc.error();

    auto r = g.finalize();

    if ( hilti::logger().isEnabled(spicy::logging::debug::Grammar) ) {
        hilti::logging::Stream dbg(spicy::logging::debug::Grammar);
        g.printTables(dbg, true);
    }

    if ( ! r )
        return r.error();

    _grammars[id] = std::move(g);
    unit->setGrammar(&_grammars[id]);
    return hilti::Nothing();
}

const Grammar* GrammarBuilder::grammar(const type::Unit& unit) {
    assert(unit.canonicalID());
    auto id = unit.canonicalID();
    if ( _grammars.find(id) != _grammars.end() )
        return &_grammars[id];
    else
        return nullptr;
}
