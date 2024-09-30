// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/type.h>

namespace hilti::type {

/** AST node for type referenced by Name. */
class Name : public UnqualifiedType {
public:
    auto id() const { return _id; }
    bool isBuiltIn() const { return _builtin; }

    // resolves recursively
    UnqualifiedType* resolvedType(size_t recursion_depth = 0) const {
        if ( ! _resolved_type_index )
            return nullptr;

        if ( recursion_depth > 1000 )
            return nullptr;

        auto t = context()->lookup(_resolved_type_index);
        if ( auto n = t->tryAs<type::Name>() )
            return n->resolvedType(recursion_depth + 1);
        else
            return t;
    }

    // resolves recursively
    declaration::Type* resolvedDeclaration() {
        if ( _resolved_type_index )
            return resolvedType()->typeDeclaration();
        else
            return nullptr;
    }

    auto resolvedTypeIndex() const { return _resolved_type_index; }
    void setResolvedTypeIndex(ast::TypeIndex index) {
        assert(index);
        _resolved_type_index = index;
    }
    void clearResolvedTypeIndex() { _resolved_type_index = ast::TypeIndex::None; }

    std::string_view typeClass() const final { return "name"; }

    node::Properties properties() const final {
        auto p =
            node::Properties{{"id", _id}, {"builtin", _builtin}, {"resolved-type", to_string(_resolved_type_index)}};
        return UnqualifiedType::properties() + p;
    }

    static auto create(ASTContext* ctx, const ID& id, Meta meta = {}) {
        return ctx->make<Name>(ctx, id, false, std::move(meta));
    }

protected:
    Name(ASTContext* ctx, ID id, bool builtin, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(meta)), _id(std::move(id)), _builtin(builtin) {}

    bool isResolved(node::CycleDetector* cd) const final;

    HILTI_NODE_1(type::Name, UnqualifiedType, final);

private:
    ID _id;
    bool _builtin;
    ast::TypeIndex _resolved_type_index;
};

} // namespace hilti::type
