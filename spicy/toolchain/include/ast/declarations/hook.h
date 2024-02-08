// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/function.h>
#include <hilti/ast/node.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/void.h>

#include <spicy/ast/engine.h>
#include <spicy/ast/forward.h>

namespace spicy {

namespace type {

class Unit;

namespace unit::item {
class Field;
}

} // namespace type

namespace declaration {

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

    Engine engine() const { return _engine; }
    auto unitTypeIndex() { return _unit_type_index; }
    auto unitFieldIndex() { return _unit_field_index; }

    ExpressionPtr priority() const {
        if ( auto attr = attributes()->find("priority") )
            return *attr->valueAsExpression();
        else
            return nullptr;
    }

    auto isForEach() const { return attributes()->has("foreach"); }
    auto isDebug() const { return attributes()->has("%debug"); }

    void setUnitTypeIndex(hilti::ast::TypeIndex index) {
        assert(index);
        _unit_type_index = index;
    }

    void setUnitFieldIndex(hilti::ast::DeclarationIndex index) {
        assert(index);
        _unit_field_index = index;
    }

    void setDDType(ASTContext* ctx, const QualifiedTypePtr& t) {
        setChild(ctx, 1, hilti::expression::Keyword::createDollarDollarDeclaration(ctx, t));
    }

    void setParameters(ASTContext* ctx, const hilti::declaration::Parameters& params) {
        ftype()->setParameters(ctx, params);
    }
    void setResult(ASTContext* ctx, const QualifiedTypePtr& t) { function()->setResultType(ctx, t); }

    std::string displayName() const override { return "Spicy hook"; }
    node::Properties properties() const final;

    static auto create(ASTContext* ctx, const hilti::declaration::Parameters& parameters, const StatementPtr& body,
                       Engine engine, AttributeSetPtr attrs, const Meta& m = Meta()) {
        if ( ! attrs )
            attrs = AttributeSet::create(ctx);

        auto ftype = hilti::type::Function::create(ctx,
                                                   QualifiedType::create(ctx, hilti::type::Void::create(ctx, m),
                                                                         hilti::Constness::Const),
                                                   parameters, hilti::type::function::Flavor::Hook, m);
        auto func = hilti::Function::create(ctx, hilti::ID(), ftype, body, hilti::function::CallingConvention::Standard,
                                            attrs, m);
        return std::shared_ptr<Hook>(new Hook(ctx, {func, nullptr}, engine, m));
    }

protected:
    Hook(ASTContext* ctx, Nodes children, Engine engine, Meta m = Meta())
        : Declaration(ctx, std::move(children), hilti::ID(), hilti::declaration::Linkage::Private, std::move(m)),
          _engine(engine) {}

    HILTI_NODE(spicy, Hook);

private:
    Engine _engine = {};
    hilti::ast::TypeIndex _unit_type_index;
    hilti::ast::DeclarationIndex _unit_field_index;
};

using HookPtr = std::shared_ptr<Hook>;
using Hooks = std::vector<HookPtr>;

} // namespace declaration
} // namespace spicy
