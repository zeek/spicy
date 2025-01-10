// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>

#include <spicy/ast/declarations/hook.h>
#include <spicy/ast/types/sink.h>
#include <spicy/ast/types/unit-item.h>

namespace spicy::type::unit::item {

/**
 * AST node for a unit field with its type determined by a not yet resolved
 * ID. The ID may refer to either a type or an ctor.
 */
class UnresolvedField : public unit::Item {
public:
    const auto& fieldID() const { return id(); }
    const auto& unresolvedID() const { return _unresolved_id; }
    const auto& index() const { return _index; }

    // Only one of these will have return value.
    auto ctor() const { return childTryAs<Ctor>(1); }
    auto item() const { return childTryAs<Item>(1); }
    auto type() const { return childTryAs<QualifiedType>(1); }

    auto repeatCount() const { return child<Expression>(2); }
    auto attributes() const { return child<AttributeSet>(3); }
    auto condition() const { return child<Expression>(4); }
    auto arguments() const { return children<Expression>(args_start, _args_end); }
    auto sinks() const { return children<Expression>(_sinks_start, _sinks_end); }
    auto hooks() const { return children<declaration::Hook>(_hooks_start, _hooks_end); }
    auto isSkip() const { return _is_skip; }

    void setIndex(uint64_t index) { _index = index; }
    void setSkip(bool skip) { _is_skip = skip; }
    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 1, t); }

    QualifiedType* itemType() const final { return child<QualifiedType>(0); /* return `auto` */ }

    bool isResolved(hilti::node::CycleDetector* cd) const final { return false; }

    std::string_view displayName() const final { return "unresolved unit field"; }

    node::Properties properties() const final {
        auto p = node::Properties{{"index", _index}};
        return unit::Item::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, ID id, QualifiedType* type, bool skip, Expressions args, Expression* repeat,
                       Expressions sinks, AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                       Meta meta = {}) {
        return _create(ctx, std::move(id), type, skip, std::move(args), repeat, std::move(sinks), attrs, cond,
                       std::move(hooks), std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, Ctor* ctor, bool skip, Expressions args, Expression* repeat,
                       Expressions sinks, AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                       Meta meta = {}) {
        return _create(ctx, std::move(id), ctor, skip, std::move(args), repeat, std::move(sinks), attrs, cond,
                       std::move(hooks), std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, type::unit::Item* item, bool skip, Expressions args, Expression* repeat,
                       Expressions sinks, AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                       Meta meta = {}) {
        return _create(ctx, std::move(id), item, skip, std::move(args), repeat, std::move(sinks), attrs, cond,
                       std::move(hooks), std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, ID unresolved_id, bool skip, Expressions args, Expression* repeat,
                       Expressions sinks, AttributeSet* attrs, Expression* cond, spicy::declaration::Hooks hooks,
                       Meta meta = {}) {
        auto f = _create(ctx, std::move(id), nullptr, skip, std::move(args), repeat, std::move(sinks), attrs, cond,
                         std::move(hooks), std::move(meta));
        f->_unresolved_id = std::move(unresolved_id);
        return f;
    }


protected:
    UnresolvedField(ASTContext* ctx, Nodes children, size_t args_start, size_t args_end, size_t sinks_start,
                    size_t sinks_end, size_t hooks_start, size_t hooks_end, ID id, bool skip, Meta meta)
        : unit::Item(ctx, NodeTags, std::move(children), std::move(id), std::move(meta)),
          _is_skip(skip),
          args_start(static_cast<int>(args_start)),
          _args_end(static_cast<int>(args_end)),
          _sinks_start(static_cast<int>(sinks_start)),
          _sinks_end(static_cast<int>(sinks_end)),
          _hooks_start(static_cast<int>(hooks_start)),
          _hooks_end(static_cast<int>(hooks_end)) {}

    SPICY_NODE_2(type::unit::item::UnresolvedField, type::unit::Item, Declaration, final);

private:
    static UnresolvedField* _create(ASTContext* ctx, ID id, Node* node, bool skip, Expressions args, Expression* repeat,
                                    Expressions sinks, AttributeSet* attrs, Expression* cond,
                                    spicy::declaration::Hooks hooks, Meta meta) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto auto_ = QualifiedType::create(ctx, hilti::type::Auto::create(ctx), hilti::Constness::Const, meta);
        auto num_args = args.size();
        auto num_sinks = sinks.size();
        auto num_hooks = hooks.size();

        return ctx->make<UnresolvedField>(ctx,
                                          node::flatten(auto_, node, repeat, attrs, cond, std::move(args),
                                                        std::move(sinks), std::move(hooks)),
                                          5U, 5U + num_args, 5U + num_args, 5U + num_args + num_sinks,
                                          5U + num_args + num_sinks, 5U + num_args + num_sinks + num_hooks,
                                          std::move(id), skip, std::move(meta));
    }

    ID _unresolved_id;
    bool _is_skip;
    std::optional<uint64_t> _index;
    const int args_start;
    const int _args_end;
    const int _sinks_start;
    const int _sinks_end;
    const int _hooks_start;
    const int _hooks_end;
};

} // namespace spicy::type::unit::item
