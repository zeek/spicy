// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/function.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/void.h>

#include <spicy/ast/attribute.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/node.h>

namespace spicy {

namespace type {

class Unit;

namespace unit::item {
class Field;
}

} // namespace type

namespace declaration {

namespace hook {

/** Type of a hook. */
enum class Type {
    /**
     * Normal hook executing when a field has received its value; or, if it's
     * life-time hook like `%init`, when time has come.
     */
    Standard,

    /** `foreach` hook for containers, executing for each element added. */
    ForEach,

    /** `%error` hook executing when an error has occurred processing the field. */
    Error,
};

namespace detail {
constexpr hilti::util::enum_::Value<Type> Types[] = {
    {.value = Type::Standard, .name = "standard"},
    {.value = Type::ForEach, .name = "foreach"},
    {.value = Type::Error, .name = "error"},
};

} // namespace detail

constexpr auto to_string(Type cc) { return hilti::util::enum_::to_string(cc, detail::Types); }
} // namespace hook

/** AST node representing a Spicy unit hook. */
class Hook : public Declaration {
public:
    ~Hook() override;

    auto function() const { return child<Function>(0); }
    auto attributes() const { return function()->attributes(); }
    auto dd() const { return child<Declaration>(1); }

    auto body() const { return function()->body(); }
    auto ftype() const { return function()->ftype(); }
    auto type() const { return function()->type(); }

    auto unitTypeIndex() { return _unit_type_index; }
    auto unitFieldIndex() { return _unit_field_index; }

    hilti::Expression* priority() const {
        if ( auto* attr = attributes()->find(attribute::kind::Priority) )
            return *attr->valueAsExpression();
        else
            return nullptr;
    }

    hook::Type hookType() const {
        if ( attributes()->find(attribute::kind::Foreach) )
            return hook::Type::ForEach;
        else if ( attributes()->find(attribute::kind::Error) )
            return hook::Type::Error;
        else
            return hook::Type::Standard;
    }

    auto isDebug() const { return attributes()->find(attribute::kind::Debug); }

    void setUnitTypeIndex(hilti::ast::TypeIndex index) {
        assert(index);
        _unit_type_index = index;
    }

    void setUnitFieldIndex(hilti::ast::DeclarationIndex index) {
        assert(index);
        _unit_field_index = index;
    }

    void setDDType(ASTContext* ctx, QualifiedType* t) {
        setChild(ctx, 1, hilti::expression::Keyword::createDollarDollarDeclaration(ctx, t));
    }

    void setParameters(ASTContext* ctx, const hilti::declaration::Parameters& params) {
        ftype()->setParameters(ctx, params);
    }
    void setResult(ASTContext* ctx, QualifiedType* t) { function()->setResultType(ctx, t); }

    std::string_view displayName() const override { return "Spicy hook"; }
    node::Properties properties() const final;

    static auto create(ASTContext* ctx, const hilti::declaration::Parameters& parameters, hilti::statement::Block* body,
                       AttributeSet* attrs, const Meta& m = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto* ftype = hilti::type::Function::create(ctx,
                                                    QualifiedType::create(ctx, hilti::type::Void::create(ctx, m),
                                                                          hilti::Constness::Const),
                                                    parameters, hilti::type::function::Flavor::Hook,
                                                    hilti::type::function::CallingConvention::Standard, m);
        auto* func = hilti::Function::create(ctx, hilti::ID(), ftype, body, attrs, m);
        return ctx->make<Hook>(ctx, {func, nullptr}, m);
    }

protected:
    Hook(ASTContext* ctx, Nodes children, Meta m = Meta())
        : Declaration(ctx, NodeTags, std::move(children), hilti::ID(), hilti::declaration::Linkage::Private,
                      std::move(m)) {}

    SPICY_NODE_1(declaration::Hook, Declaration, final);

private:
    hilti::ast::TypeIndex _unit_type_index;
    hilti::ast::DeclarationIndex _unit_field_index;
};

using Hooks = NodeVector<Hook>;

} // namespace declaration
} // namespace spicy
