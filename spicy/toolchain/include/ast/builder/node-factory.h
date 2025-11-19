// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

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

    auto ctorUnit(const ctor::unit::Fields& fields, QualifiedType* t, Meta meta = {}) {
        return spicy::ctor::Unit::create(context(), fields, t, std::move(meta));
    }
    auto ctorUnit(const ctor::unit::Fields& fields, Meta meta = {}) {
        return spicy::ctor::Unit::create(context(), fields, std::move(meta));
    }
    auto declarationHook(const hilti::declaration::Parameters& parameters, hilti::statement::Block* body,
                         AttributeSet* attrs, const Meta& m = Meta()) {
        return spicy::declaration::Hook::create(context(), parameters, body, attrs, m);
    }
    auto declarationUnitHook(const ID& id, declaration::Hook* hook, Meta meta = {}) {
        return spicy::declaration::UnitHook::create(context(), id, hook, std::move(meta));
    }
    auto statementConfirm(Meta meta = {}) { return spicy::statement::Confirm::create(context(), std::move(meta)); }
    auto statementPrint(const Expressions& expressions, Meta meta = {}) {
        return spicy::statement::Print::create(context(), expressions, std::move(meta));
    }
    auto statementReject(Meta meta = {}) { return spicy::statement::Reject::create(context(), std::move(meta)); }
    auto statementStop(Meta meta = {}) { return spicy::statement::Stop::create(context(), std::move(meta)); }
    auto typeSink(Meta meta = {}) { return spicy::type::Sink::create(context(), std::move(meta)); }
    auto typeUnit(const hilti::declaration::Parameters& params, const type::unit::Items& items, AttributeSet* attrs,
                  Meta meta = {}) {
        return spicy::type::Unit::create(context(), params, items, attrs, std::move(meta));
    }
    auto typeUnit(hilti::type::Wildcard _, Meta meta = {}) {
        return spicy::type::Unit::create(context(), _, std::move(meta));
    }
    auto typeUnitItemBlock(const type::unit::Items& items, AttributeSet* attrs = nullptr, const Meta& m = Meta()) {
        return spicy::type::unit::item::Block::create(context(), items, nullptr, {}, attrs, m);
    }
    auto typeUnitItemBlock(Expression* condition, const type::unit::Items& true_items,
                           const type::unit::Items& false_items = {}, AttributeSet* attrs = nullptr,
                           const Meta& m = Meta()) {
        return spicy::type::unit::item::Block::create(context(), true_items, condition, false_items, attrs, m);
    }
    auto typeUnitItemField(const ID& id, Ctor* ctor, bool skip, Expressions args, Expression* repeat, Expressions sinks,
                           AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks, Meta meta = {}) {
        return spicy::type::unit::item::Field::create(context(), id, ctor, skip, std::move(args), repeat,
                                                      std::move(sinks), attrs, cond, std::move(hooks), std::move(meta));
    }
    auto typeUnitItemField(const ID& id, QualifiedType* type, bool skip, Expressions args, Expression* repeat,
                           Expressions sinks, AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                           Meta meta = {}) {
        return spicy::type::unit::item::Field::create(context(), id, type, skip, std::move(args), repeat,
                                                      std::move(sinks), attrs, cond, std::move(hooks), std::move(meta));
    }
    auto typeUnitItemField(const ID& id, type::unit::Item* item, bool skip, Expressions args, Expression* repeat,
                           Expressions sinks, AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                           Meta meta = {}) {
        return spicy::type::unit::item::Field::create(context(), id, item, skip, std::move(args), repeat,
                                                      std::move(sinks), attrs, cond, std::move(hooks), std::move(meta));
    }
    auto typeUnitItemProperty(ID id, AttributeSet* attrs, bool inherited = false, Meta meta = {}) {
        return spicy::type::unit::item::Property::create(context(), std::move(id), attrs, inherited, std::move(meta));
    }
    auto typeUnitItemProperty(ID id, Expression* expr, AttributeSet* attrs, bool inherited = false, Meta meta = {}) {
        return spicy::type::unit::item::Property::create(context(), std::move(id), expr, attrs, inherited,
                                                         std::move(meta));
    }
    auto typeUnitItemSink(ID id, AttributeSet* attrs, Meta meta = {}) {
        return spicy::type::unit::item::Sink::create(context(), std::move(id), attrs, std::move(meta));
    }
    auto typeUnitItemSwitch(Expression* expr, type::unit::item::switch_::Cases cases, Expression* cond,
                            spicy::declaration::Hooks hooks, AttributeSet* attrs, Meta meta = {}) {
        return spicy::type::unit::item::Switch::create(context(), expr, std::move(cases), cond, std::move(hooks), attrs,
                                                       std::move(meta));
    }
    auto typeUnitItemSwitchCase(const Expressions& exprs, const type::unit::Items& items, const Meta& m = Meta()) {
        return spicy::type::unit::item::switch_::Case::create(context(), exprs,
                                                              spicy::type::unit::item::Block::create(context(), items,
                                                                                                     nullptr, {},
                                                                                                     nullptr, m),
                                                              m);
    }
    auto typeUnitItemSwitchCase(const type::unit::Items& items, bool use_look_ahead, const Meta& m = Meta()) {
        return spicy::type::unit::item::switch_::Case::create(context(),
                                                              spicy::type::unit::item::Block::create(context(), items,
                                                                                                     nullptr, {},
                                                                                                     nullptr, m),
                                                              use_look_ahead, m);
    }
    auto typeUnitItemUnitHook(const ID& id, spicy::declaration::Hook* hook, Meta meta = {}) {
        return spicy::type::unit::item::UnitHook::create(context(), id, hook, std::move(meta));
    }
    auto typeUnitItemUnresolvedField(ID id, Ctor* ctor, bool skip, Expressions args, Expression* repeat,
                                     Expressions sinks, AttributeSet* attrs, Expression* cond,
                                     spicy::declaration::Hooks hooks, Meta meta = {}) {
        return spicy::type::unit::item::UnresolvedField::create(context(), std::move(id), ctor, skip, std::move(args),
                                                                repeat, std::move(sinks), attrs, cond, std::move(hooks),
                                                                std::move(meta));
    }
    auto typeUnitItemUnresolvedField(ID id, ID unresolved_id, bool skip, Expressions args, Expressions sinks,
                                     AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                                     Meta meta = {}) {
        return spicy::type::unit::item::UnresolvedField::create(context(), std::move(id), std::move(unresolved_id),
                                                                skip, std::move(args), {}, std::move(sinks), attrs,
                                                                cond, std::move(hooks), std::move(meta));
    }
    auto typeUnitItemUnresolvedField(ID id, QualifiedType* type, bool skip, Expressions args, Expressions sinks,
                                     AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                                     Meta meta = {}) {
        return spicy::type::unit::item::UnresolvedField::create(context(), std::move(id), type, skip, std::move(args),
                                                                {}, std::move(sinks), attrs, cond, std::move(hooks),
                                                                std::move(meta));
    }
    auto typeUnitItemUnresolvedField(ID id, type::unit::Item* item, bool skip, Expressions args, Expression* repeat,
                                     Expressions sinks, AttributeSet* attrs, Expression* cond,
                                     spicy::declaration::Hooks hooks, Meta meta = {}) {
        return spicy::type::unit::item::UnresolvedField::create(context(), std::move(id), item, skip, std::move(args),
                                                                repeat, std::move(sinks), attrs, cond, std::move(hooks),
                                                                std::move(meta));
    }
    auto typeUnitItemVariable(ID id, QualifiedType* type, Expression* default_, AttributeSet* attrs, Meta meta = {}) {
        return spicy::type::unit::item::Variable::create(context(), std::move(id), type, default_, attrs,
                                                         std::move(meta));
    }


private:
    ASTContext* _context;
};

} // namespace spicy::builder
