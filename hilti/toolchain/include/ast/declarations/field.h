
// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::declaration {

/** AST node for a struct/union field. */
class Field : public DeclarationBase {
public:
    Field() : DeclarationBase({ID("<no id>"), type::unknown, node::none, node::none}, Meta()) {}
    Field(ID id, hilti::Type t, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(t), std::move(attrs), node::none), std::move(m)) {}
    Field(ID id, ::hilti::function::CallingConvention cc, type::Function ft, std::optional<AttributeSet> attrs = {},
          Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), std::move(ft), std::move(attrs), node::none), std::move(m)), _cc(cc) {}
    Field(ID id, const hilti::Function& inline_func, std::optional<AttributeSet> attrs = {}, Meta m = Meta())
        : DeclarationBase(nodes(std::move(id), node::none, std::move(attrs), inline_func), std::move(m)),
          _cc(inline_func.callingConvention()) {}

    const auto& id() const { return child<ID>(0); }

    auto callingConvention() const { return _cc; }
    auto inlineFunction() const { return children()[3].tryAs<hilti::Function>(); }
    auto attributes() const { return children()[2].tryAs<AttributeSet>(); }
    bool isResolved(type::ResolvedState* rstate) const {
        if ( children()[1].isA<type::Function>() )
            return true;

        if ( auto func = inlineFunction() )
            return type::detail::isResolved(func->type(), rstate);
        else
            return type::detail::isResolved(child<hilti::Type>(1), rstate);
    }

    const hilti::Type& type() const {
        if ( const auto& func = inlineFunction() )
            return func->type();
        else
            return child<hilti::Type>(1);
    }

    NodeRef typeRef() {
        if ( inlineFunction() )
            return children()[3].as<hilti::Function>().typeRef();
        else
            return NodeRef(children()[1]);
    }

    hilti::optional_ref<const hilti::Expression> default_() const {
        if ( auto a = AttributeSet::find(attributes(), "&default") ) {
            if ( auto x = a->valueAsExpression() )
                return x->get();
            else
                return {};
        }

        return {};
    }

    auto isInternal() const { return AttributeSet::find(attributes(), "&internal").has_value(); }
    auto isOptional() const { return AttributeSet::find(attributes(), "&optional").has_value(); }
    auto isStatic() const { return AttributeSet::find(attributes(), "&static").has_value(); }
    auto isNoEmit() const { return AttributeSet::find(attributes(), "&no-emit").has_value(); }

    /** Internal method for use by builder API only. */
    auto& _typeNode() {
        if ( auto func = inlineFunction() )
            return const_cast<::hilti::Function&>(*func)._typeNode();
        else
            return children()[1];
    }

    void setAttributes(const AttributeSet& attrs) { children()[2] = attrs; }

    bool operator==(const Field& other) const {
        return id() == other.id() && type() == other.type() && attributes() == other.attributes() && _cc == other._cc;
    }

    /** Implements the `Declaration` interface. */
    declaration::Linkage linkage() const { return declaration::Linkage::Struct; }

    /** Implements the `Declaration` interface. */
    bool isConstant() const { return false; }

    /** Implements the `Declaration` interface. */
    std::string displayName() const { return "struct field"; }

    /** Implements the `Declaration` interface. */
    auto isEqual(const Declaration& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"cc", to_string(_cc)}}; }

private:
    ::hilti::function::CallingConvention _cc = ::hilti::function::CallingConvention::Standard;
}; // namespace struct_

} // namespace hilti::declaration
