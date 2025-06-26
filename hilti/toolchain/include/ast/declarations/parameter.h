// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <string_view>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/unknown.h>


namespace hilti::parameter {

/** Type of a `Parameter`. */
enum class Kind {
    Unknown, /**< not specified */
    Copy,    /**< `copy` parameter */
    In,      /**< `in` parameter */
    InOut    /**< `inout` parameter */
};

namespace detail {
constexpr util::enum_::Value<Kind> Kinds[] = {
    {.value = Kind::Unknown, .name = "unknown"},
    {.value = Kind::Copy, .name = "copy"},
    {.value = Kind::In, .name = "in"},
    {.value = Kind::InOut, .name = "inout"},
};
} // namespace detail

constexpr auto to_string(Kind k) { return util::enum_::to_string(k, detail::Kinds); }

namespace kind {
constexpr auto from_string(std::string_view s) { return util::enum_::from_string<Kind>(s, detail::Kinds); }
} // namespace kind

} // namespace hilti::parameter

namespace hilti::declaration {

/** AST node for a parameter declaration. */
class Parameter : public Declaration {
public:
    auto attributes() const { return child<AttributeSet>(2); }
    auto default_() const { return child<hilti::Expression>(1); }
    auto kind() const { return _kind; }
    auto type() const { return child<hilti::QualifiedType>(0); }
    auto isTypeParameter() const { return _is_type_param; }
    auto isResolved(node::CycleDetector* cd = nullptr) const { return type()->isResolved(cd); }

    void setDefault(ASTContext* ctx, hilti::Expression* e) { setChild(ctx, 1, e); }
    void setIsTypeParameter() { _is_type_param = true; }
    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    std::string_view displayName() const final { return "parameter"; }

    node::Properties properties() const final {
        auto p = node::Properties{{"kind", to_string(_kind)}, {"is_type_param", _is_type_param}};
        return Declaration::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, ID id, UnqualifiedType* type, parameter::Kind kind, hilti::Expression* default_,
                       AttributeSet* attrs, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Parameter>(ctx, {_qtype(ctx, type, kind), default_, attrs}, std::move(id), kind, false,
                                    std::move(meta));
    }

    static auto create(ASTContext* ctx, ID id, UnqualifiedType* type, parameter::Kind kind, hilti::Expression* default_,
                       bool is_type_param, AttributeSet* attrs, Meta meta = {}) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        return ctx->make<Parameter>(ctx, {_qtype(ctx, type, kind), default_, attrs}, std::move(id), kind, is_type_param,
                                    std::move(meta));
    }

protected:
    Parameter(ASTContext* ctx, Nodes children, ID id, parameter::Kind kind, bool is_type_param, Meta meta)
        : Declaration(ctx, NodeTags, std::move(children), std::move(id), Linkage::Private, std::move(meta)),
          _kind(kind),
          _is_type_param(is_type_param) {}

    std::string _dump() const override { return isResolved() ? "(resolved)" : "(not resolved)"; }

    HILTI_NODE_1(declaration::Parameter, Declaration, final);

private:
    static QualifiedType* _qtype(ASTContext* ctx, UnqualifiedType* t, parameter::Kind kind) {
        switch ( kind ) {
            case parameter::Kind::Copy: return QualifiedType::create(ctx, t, Constness::Mutable, Side::LHS, t->meta());
            case parameter::Kind::In: return QualifiedType::create(ctx, t, Constness::Const, Side::RHS, t->meta());
            case parameter::Kind::InOut: return QualifiedType::create(ctx, t, Constness::Mutable, Side::LHS, t->meta());
            default:
                return QualifiedType::create(ctx, type::Unknown::create(ctx), Constness::Const, Side::RHS, t->meta());
        }
    }

    parameter::Kind _kind = parameter::Kind::Unknown;
    bool _is_type_param = false;
};

using Parameters = NodeVector<Parameter>;

} // namespace hilti::declaration

namespace hilti::declaration {

/** Returns true if two parameters are different only by name of their ID. */
inline bool areEquivalent(Parameter* p1, Parameter* p2) {
    if ( p1->kind() != p2->kind() )
        return false;

    if ( (p1->default_() && ! p2->default_()) || (p2->default_() && ! p1->default_()) )
        return false;

    if ( p1->default_() && p2->default_() && p1->default_()->print() != p2->default_()->print() )
        return false;

    auto auto1 = p1->type()->type()->isA<type::Auto>();
    auto auto2 = p2->type()->type()->isA<type::Auto>();

    if ( auto1 || auto2 )
        return true;

    return type::same(p1->type(), p2->type());
}

/** Returns true if two sets of parameters are equivalent, regardless of their ID. */
inline bool areEquivalent(const node::Set<Parameter>& params1, const node::Set<Parameter>& params2) {
    return std::equal(params1.begin(), params1.end(), params2.begin(), params2.end(),
                      [](const auto& p1, const auto& p2) { return areEquivalent(p1, p2); });
}

} // namespace hilti::declaration
