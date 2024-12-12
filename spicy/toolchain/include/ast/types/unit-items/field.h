// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/base/uniquer.h>

#include <spicy/ast/declarations/hook.h>
#include <spicy/ast/types/sink.h>
#include <spicy/ast/types/unit-item.h>
#include <spicy/ast/types/unit-items/unit-hook.h>

namespace spicy::type::unit::item {

/** AST node for a unit field. */
class Field : public unit::Item {
public:
    const auto& index() const { return _index; }

    // Only one of these will have return value.
    auto ctor() const { return childTryAs<Ctor>(4); }
    auto item() const { return childTryAs<Item>(4); }
    auto type() const { return childTryAs<QualifiedType>(4); }

    auto repeatCount() const { return child<Expression>(5); }
    auto attributes() const { return child<AttributeSet>(6); }
    auto condition() const { return child<Expression>(7); }
    auto arguments() const { return children<Expression>(_args_start, _args_end); }
    auto sinks() const { return children<Expression>(_sinks_start, _sinks_end); }
    auto hooks() const { return children<declaration::Hook>(_hooks_start, _hooks_end); }

    auto isSkip() const { return _is_skip; }
    auto isContainer() const { return repeatCount() != nullptr; }
    auto isForwarding() const { return _is_forwarding; }
    auto isTransient() const { return _is_transient; }
    auto isAnonymous() const { return _is_anonymous; }
    auto emitHook() const { return ! isAnonymous() || hooks().size(); }

    QualifiedType* originalType() const {
        if ( auto t = child<QualifiedType>(1) )
            return t;

        if ( auto c = ctor() )
            return c->type();

        if ( auto i = item() )
            return i->itemType();

        hilti::util::cannotBeReached();
    }

    auto parseType() const { return child<QualifiedType>(2); }

    QualifiedType* ddType() const {
        if ( auto x = childTryAs<hilti::declaration::Expression>(0) )
            return x->expression()->type();
        else
            return child<QualifiedType>(0); // `auto` by default
    }

    Declaration* dd() const {
        if ( auto x = childTryAs<hilti::declaration::Expression>(0) )
            return x;
        else
            return {};
    }

    /** Get the `&convert` expression, if any. */
    std::optional<std::pair<Expression*, QualifiedType*>> convertExpression() const;

    void setForwarding(bool is_forwarding) { _is_forwarding = is_forwarding; }
    void setTransient(bool is_transient) { _is_transient = is_transient; }
    void setDDType(ASTContext* ctx, QualifiedType* t);
    void setIndex(uint64_t index) { _index = index; }
    void setItemType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 3, t); }
    void setParseType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 2, t); }
    void setSkip(bool skip) { _is_skip = skip; }

    QualifiedType* itemType() const final { return child<QualifiedType>(3); }

    bool isResolved(hilti::node::CycleDetector* cd) const final {
        return type() || item() || itemType()->isResolved(cd);
    }

    std::string_view displayName() const final { return "unit field"; }

    node::Properties properties() const final {
        auto p = node::Properties{{"anonymous", _is_anonymous},
                                  {"transient", _is_transient},
                                  {"forwarding", _is_forwarding},
                                  {"index", _index},
                                  {"skip", _is_skip}};
        return unit::Item::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, const ID& id, QualifiedType* type, bool skip, Expressions args,
                       Expression* repeat, Expressions sinks, AttributeSet* attrs, Expression* cond,
                       spicy::declaration::Hooks hooks, Meta meta = {}) {
        return _create(ctx, id, type, type, skip, std::move(args), repeat, std::move(sinks), attrs, cond,
                       std::move(hooks), std::move(meta));
    }

    static auto create(ASTContext* ctx, const ID& id, Ctor* ctor, bool skip, Expressions args, Expression* repeat,
                       Expressions sinks, AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                       Meta meta = {}) {
        return _create(ctx, id, nullptr, ctor, skip, std::move(args), repeat, std::move(sinks), attrs, cond,
                       std::move(hooks), std::move(meta));
    }

    static auto create(ASTContext* ctx, const ID& id, type::unit::Item* item, bool skip, Expressions args,
                       Expression* repeat, Expressions sinks, AttributeSet* attrs, Expression* cond,
                       spicy::declaration::Hooks hooks, Meta meta = {}) {
        return _create(ctx, id, nullptr, item, skip, std::move(args), repeat, std::move(sinks), attrs, cond,
                       std::move(hooks), std::move(meta));
    }

protected:
    Field(ASTContext* ctx, Nodes children, size_t args_start, size_t args_end, size_t sinks_start, size_t sinks_end,
          size_t hooks_start, size_t hooks_end, const ID& id, bool skip, Meta meta)
        : unit::Item(ctx, NodeTags, std::move(children), (id ? id : _uniquer.get("_anon", false)), std::move(meta)),
          _is_anonymous(! id),
          _is_skip(skip),
          _args_start(static_cast<int>(args_start)),
          _args_end(static_cast<int>(args_end)),
          _sinks_start(static_cast<int>(sinks_start)),
          _sinks_end(static_cast<int>(sinks_end)),
          _hooks_start(static_cast<int>(hooks_start)),
          _hooks_end(static_cast<int>(hooks_end)) {}

    SPICY_NODE_2(type::unit::item::Field, type::unit::Item, Declaration, final);

private:
    static Field* _create(ASTContext* ctx, const ID& id, QualifiedType* org_type, Node* node, bool skip,
                          Expressions args, Expression* repeat, Expressions sinks, AttributeSet* attrs,
                          Expression* cond, spicy::declaration::Hooks hooks, Meta meta) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto auto_ = QualifiedType::create(ctx, hilti::type::Auto::create(ctx), hilti::Constness::Const, meta);
        auto num_args = args.size();
        auto num_sinks = sinks.size();
        auto num_hooks = hooks.size();

        return ctx->make<Field>(ctx,
                                node::flatten(auto_, org_type, auto_, auto_, node, repeat, attrs, cond, std::move(args),
                                              std::move(sinks), std::move(hooks)),
                                8U, 8U + num_args, 8U + num_args, 8U + num_args + num_sinks, 8U + num_args + num_sinks,
                                8U + num_args + num_sinks + num_hooks, id, skip, std::move(meta));
    }

    bool _is_forwarding = false;
    bool _is_transient = false;
    bool _is_anonymous;
    bool _is_skip;
    std::optional<uint64_t> _index;
    const int _args_start;
    const int _args_end;
    const int _sinks_start;
    const int _sinks_end;
    const int _hooks_start;
    const int _hooks_end;

    static inline hilti::util::Uniquer<ID> _uniquer;
};

} // namespace spicy::type::unit::item
