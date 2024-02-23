// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/builder/node-factory.h>

#include <spicy/ast/all.h>

namespace spicy::builder {

/** Base class making node factory methods available. */
class NodeFactory {
public:
    /**
     * Constructor.
     *
     * @param context AST context to use for creating nodes.
     */
    NodeFactory(ASTContext* context) : _context(context) {}

    /** Returns the AST context in use for creating nodes. */
    ASTContext* context() const { return _context; }

    auto ctorUnit(ctor::unit::Fields fields, QualifiedTypePtr t, const Meta& meta = {}) {
        return spicy::ctor::Unit::create(context(), fields, t, meta);
    }
    auto ctorUnit(ctor::unit::Fields fields, const Meta& meta = {}) {
        return spicy::ctor::Unit::create(context(), fields, meta);
    }
    auto declarationHook(const hilti::declaration::Parameters& parameters, const StatementPtr& body, Engine engine,
                         AttributeSetPtr attrs, const Meta& m = Meta()) {
        return spicy::declaration::Hook::create(context(), parameters, body, engine, attrs, m);
    }
    auto declarationUnitHook(const ID& id, const declaration::HookPtr& hook, Meta meta = {}) {
        return spicy::declaration::UnitHook::create(context(), id, hook, meta);
    }
    auto statementConfirm(Meta meta = {}) { return spicy::statement::Confirm::create(context(), meta); }
    auto statementPrint(Expressions expressions, Meta meta = {}) {
        return spicy::statement::Print::create(context(), expressions, meta);
    }
    auto statementReject(Meta meta = {}) { return spicy::statement::Reject::create(context(), meta); }
    auto statementStop(Meta meta = {}) { return spicy::statement::Stop::create(context(), meta); }
    auto typeSink(const Meta& meta = {}) { return spicy::type::Sink::create(context(), meta); }
    auto typeUnit(const hilti::declaration::Parameters& params, type::unit::Items items, AttributeSetPtr attrs,
                  const Meta& meta = {}) {
        return spicy::type::Unit::create(context(), params, items, attrs, meta);
    }
    auto typeUnit(hilti::type::Wildcard _, const Meta& meta = {}) {
        return spicy::type::Unit::create(context(), _, meta);
    }
    auto typeUnitItemField(const ID& id, CtorPtr ctor, Engine engine, bool skip, Expressions args, ExpressionPtr repeat,
                           Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                           spicy::declaration::Hooks hooks, const Meta& meta = {}) {
        return spicy::type::unit::item::Field::create(context(), id, ctor, engine, skip, args, repeat, sinks, attrs,
                                                      cond, hooks, meta);
    }
    auto typeUnitItemField(const ID& id, const QualifiedTypePtr& type, Engine engine, bool skip, Expressions args,
                           ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                           spicy::declaration::Hooks hooks, const Meta& meta = {}) {
        return spicy::type::unit::item::Field::create(context(), id, type, engine, skip, args, repeat, sinks, attrs,
                                                      cond, hooks, meta);
    }
    auto typeUnitItemField(const ID& id, type::unit::ItemPtr item, Engine engine, bool skip, Expressions args,
                           ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                           spicy::declaration::Hooks hooks, const Meta& meta = {}) {
        return spicy::type::unit::item::Field::create(context(), id, item, engine, skip, args, repeat, sinks, attrs,
                                                      cond, hooks, meta);
    }
    auto typeUnitItemProperty(ID id, AttributeSetPtr attrs, bool inherited = false, const Meta& meta = {}) {
        return spicy::type::unit::item::Property::create(context(), id, attrs, inherited, meta);
    }
    auto typeUnitItemProperty(ID id, ExpressionPtr expr, AttributeSetPtr attrs, bool inherited = false,
                              const Meta& meta = {}) {
        return spicy::type::unit::item::Property::create(context(), id, expr, attrs, inherited, meta);
    }
    auto typeUnitItemSink(ID id, AttributeSetPtr attrs, const Meta& meta = {}) {
        return spicy::type::unit::item::Sink::create(context(), id, attrs, meta);
    }
    auto typeUnitItemSwitch(ExpressionPtr expr, type::unit::item::switch_::Cases cases, Engine engine,
                            ExpressionPtr cond, spicy::declaration::Hooks hooks, AttributeSetPtr attrs,
                            const Meta& meta = {}) {
        return spicy::type::unit::item::Switch::create(context(), expr, cases, engine, cond, hooks, attrs, meta);
    }
    auto typeUnitItemSwitchCase(const Expressions& exprs, const type::unit::Items& items, const Meta& m = Meta()) {
        return spicy::type::unit::item::switch_::Case::create(context(), exprs, items, m);
    }
    auto typeUnitItemSwitchCase(const type::unit::ItemPtr& field, const Meta& m = Meta()) {
        return spicy::type::unit::item::switch_::Case::create(context(), field, m);
    }
    auto typeUnitItemSwitchCase(const type::unit::Items& items, const Meta& m = Meta()) {
        return spicy::type::unit::item::switch_::Case::create(context(), items, m);
    }
    auto typeUnitItemUnitHook(const ID& id, spicy::declaration::HookPtr hook, const Meta& meta = {}) {
        return spicy::type::unit::item::UnitHook::create(context(), id, hook, meta);
    }
    auto typeUnitItemUnresolvedField(ID id, CtorPtr ctor, Engine engine, bool skip, Expressions args,
                                     ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                                     spicy::declaration::Hooks hooks, const Meta& meta = {}) {
        return spicy::type::unit::item::UnresolvedField::create(context(), id, ctor, engine, skip, args, repeat, sinks,
                                                                attrs, cond, hooks, meta);
    }
    auto typeUnitItemUnresolvedField(ID id, ID unresolved_id, Engine engine, bool skip, Expressions args,
                                     ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                                     spicy::declaration::Hooks hooks, const Meta& meta = {}) {
        return spicy::type::unit::item::UnresolvedField::create(context(), id, unresolved_id, engine, skip, args,
                                                                repeat, sinks, attrs, cond, hooks, meta);
    }
    auto typeUnitItemUnresolvedField(ID id, QualifiedTypePtr type, Engine engine, bool skip, Expressions args,
                                     ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                                     spicy::declaration::Hooks hooks, const Meta& meta = {}) {
        return spicy::type::unit::item::UnresolvedField::create(context(), id, type, engine, skip, args, repeat, sinks,
                                                                attrs, cond, hooks, meta);
    }
    auto typeUnitItemUnresolvedField(ID id, type::unit::ItemPtr item, Engine engine, bool skip, Expressions args,
                                     ExpressionPtr repeat, Expressions sinks, AttributeSetPtr attrs, ExpressionPtr cond,
                                     spicy::declaration::Hooks hooks, const Meta& meta = {}) {
        return spicy::type::unit::item::UnresolvedField::create(context(), id, item, engine, skip, args, repeat, sinks,
                                                                attrs, cond, hooks, meta);
    }
    auto typeUnitItemVariable(ID id, QualifiedTypePtr type, ExpressionPtr default_, AttributeSetPtr attrs,
                              const Meta& meta = {}) {
        return spicy::type::unit::item::Variable::create(context(), id, type, default_, attrs, meta);
    }


private:
    ASTContext* _context;
};

} // namespace spicy::builder
