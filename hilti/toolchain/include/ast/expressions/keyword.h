// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>

namespace hilti::expression {

namespace keyword {
// Type of a reserved keyword
enum class Kind {
    Self,         /**< `self` */
    DollarDollar, /**< `$$` */
    Captures,     /**< `$@` */
    Scope         /**< `$scope`*/
};

namespace detail {
constexpr util::enum_::Value<Kind> Kinds[] = {{.value = Kind::Self, .name = "self"},
                                              {.value = Kind::DollarDollar, .name = "$$"},
                                              {.value = Kind::Captures, .name = "$@"},
                                              {.value = Kind::Scope, .name = "$scope"}};
} // namespace detail

namespace kind {
constexpr auto from_string(std::string_view s) { return util::enum_::from_string<Kind>(s, detail::Kinds); }
} // namespace kind

constexpr auto to_string(Kind m) { return util::enum_::to_string(m, detail::Kinds); }

} // namespace keyword

/** AST node for an expression representing a reserved keyword. */
class Keyword : public Expression {
public:
    keyword::Kind kind() const { return _kind; }
    void setType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{{"kind", to_string(_kind)}}};
        return Expression::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, keyword::Kind kind, QualifiedType* type, Meta meta = {}) {
        return ctx->make<Keyword>(ctx, {type}, kind, std::move(meta));
    }

    static auto create(ASTContext* ctx, keyword::Kind kind, const Meta& meta = {}) {
        return create(ctx, kind, QualifiedType::createAuto(ctx, meta), meta);
    }

    /** Helper to create `$$` a declaration of a given type. */
    static auto createDollarDollarDeclaration(ASTContext* ctx, QualifiedType* type) {
        auto* kw = create(ctx, keyword::Kind::DollarDollar, type);
        return declaration::Expression::create(ctx, ID(HILTI_INTERNAL_ID("dd")), kw,
                                               hilti::declaration::Linkage::Private);
    }

protected:
    Keyword(ASTContext* ctx, Nodes children, keyword::Kind kind, Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)), _kind(kind) {}

    HILTI_NODE_1(expression::Keyword, Expression, final);

private:
    keyword::Kind _kind;
};

inline std::ostream& operator<<(std::ostream& stream, const Keyword& keyword) {
    switch ( keyword.kind() ) {
        case keyword::Kind::Self: return stream << "<self>";
        case keyword::Kind::DollarDollar: return stream << "<$$>";
        case keyword::Kind::Captures: return stream << "<captures>";
        case keyword::Kind::Scope: return stream << "<scope>";
    }

    return stream;
}

} // namespace hilti::expression
