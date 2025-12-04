// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/optional.h>

namespace hilti::type {

class Bitfield;

namespace bitfield {

/** AST node for a bitfield element. */
class BitRange final : public Declaration {
public:
    ~BitRange() final;

    auto lower() const { return _lower; }
    auto upper() const { return _upper; }
    auto fieldWidth() const { return _field_width; }

    auto itemType() const { // returns the integer type (not wrapped into an optional)
        if ( child<QualifiedType>(0)->type()->isA<type::Optional>() )
            return child<QualifiedType>(0)->type()->as<type::Optional>()->dereferencedType();
        else
            return child<QualifiedType>(0);
    }

    // TODO: Remove this and change the internal representation to not use an optional.
    auto itemTypeWithOptional() const { // return the integer type wrapped into an optional
        return child<QualifiedType>(0);
    }

    auto attributes() const { return child<AttributeSet>(1); }
    auto ctorValue() const { return child<Expression>(2); }
    auto dd() const { return child<declaration::Expression>(3); }
    auto ddType() const { return dd()->expression()->type(); }

    std::string_view displayName() const final { return "bit range"; }

    node::Properties properties() const final {
        auto p = node::Properties{
            {"lower", _lower},
            {"upper", _upper},
            {"field_width", _field_width},
        };

        return Declaration::properties() + std::move(p);
    }

    void setItemTypeWithOptional(ASTContext* ctx, QualifiedType* t) {
        assert(t->type()->isA<type::Optional>());
        setChild(ctx, 0, t);
    }

    void setAttributes(ASTContext* ctx, AttributeSet* attrs) { setChild(ctx, 1, attrs); }
    void setCtorValue(ASTContext* ctx, Expression* e) { setChild(ctx, 2, e); }

    static auto create(ASTContext* ctx, const ID& id, unsigned int lower, unsigned int upper, unsigned int field_width,
                       AttributeSet* attrs = {}, Expression* ctor_value = nullptr, Meta meta = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto* dd = expression::Keyword::createDollarDollarDeclaration(
            ctx, QualifiedType::create(ctx, type::UnsignedInteger::create(ctx, field_width), Constness::Const));

        return ctx->make<BitRange>(ctx, node::flatten(QualifiedType::createAuto(ctx), attrs, ctor_value, dd), id, lower,
                                   upper, field_width, std::move(meta));
    }

    static auto create(ASTContext* ctx, const ID& id, unsigned int lower, unsigned int upper, unsigned int field_width,
                       AttributeSet* attrs = {}, Meta meta = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return create(ctx, id, lower, upper, field_width, attrs, nullptr, std::move(meta));
    }

protected:
    friend class type::Bitfield;

    BitRange(ASTContext* ctx, Nodes children, ID id, unsigned int lower, unsigned int upper, unsigned int field_width,
             Meta meta = {})
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), declaration::Linkage::Private,
                      std::move(meta)),
          _lower(lower),
          _upper(upper),
          _field_width(field_width) {}

    HILTI_NODE_1(type::bitfield::BitRange, Declaration, final);

private:
    unsigned int _lower = 0;
    unsigned int _upper = 0;
    unsigned int _field_width = 0;
};

using BitRanges = NodeVector<BitRange>;

} // namespace bitfield

/** AST node for a `bitfield` type. */
class Bitfield : public UnqualifiedType, public node::WithUniqueID {
public:
    auto width() const { return _width; }
    auto attributes() const { return child<AttributeSet>(0); }

    auto bits(bool include_hidden = false) const {
        if ( include_hidden )
            return children<bitfield::BitRange>(1, {});
        else
            return children<bitfield::BitRange>(1, -1);
    }

    bitfield::BitRange* bits(const ID& id) const;
    std::optional<unsigned int> bitsIndex(const ID& id) const;

    /**
     * If at least one of the bits comes with a pre-defined value, this builds
     * a bitfield ctor value that corresponds to all values defined by any of
     * the bits. If none does, return nothing.
     */
    Ctor* ctorValue(ASTContext* ctx);

    void addField(ASTContext* ctx, bitfield::BitRange* f) { addChild(ctx, f); }

    std::string_view typeClass() const final { return "bitfield"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final {
        auto bs = bits();
        return std::ranges::all_of(bs, [&](const auto& b) { return b->itemType()->isResolved(cd); });
    }

    node::Properties properties() const final {
        auto p = node::Properties{{"width", _width}};
        return UnqualifiedType::properties() + node::WithUniqueID::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, unsigned int width, const type::bitfield::BitRanges& bits, AttributeSet* attrs,
                       const Meta& m = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto* value = bitfield::BitRange::create(ctx, ID(HILTI_INTERNAL_ID("value")), 0, width - 1, width, {}, m);
        return ctx->make<Bitfield>(ctx, node::flatten(attrs, bits, value), width, m);
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Bitfield>(ctx, Wildcard(), m);
    }

protected:
    Bitfield(ASTContext* ctx, Nodes children, unsigned int width, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)),
          WithUniqueID("bitfield"),
          _width(width) {}

    Bitfield(ASTContext* ctx, Wildcard _, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"bitfield(*)"}, std::move(meta)), WithUniqueID("bitfield") {}

    HILTI_NODE_1(type::Bitfield, UnqualifiedType, final);

private:
    unsigned int _width = 0;
};


} // namespace hilti::type
