// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/function.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>

namespace hilti::type {

/** AST node for a `union` type. */
class Union : public UnqualifiedType {
public:
    auto fields() const { return childrenOfType<declaration::Field>(); }

    declaration::Field* field(const ID& id) const {
        for ( const auto& f : fields() ) {
            if ( f->id() == id )
                return f;
        }

        return {};
    }

    hilti::node::Set<declaration::Field> fields(const ID& id) const {
        hilti::node::Set<declaration::Field> x;
        for ( const auto& f : fields() ) {
            if ( f->id() == id )
                x.push_back(f);
        }

        return x;
    }

    unsigned int index(const ID& id) const {
        for ( const auto&& [i, f] : util::enumerate(fields()) ) {
            if ( f->id() == id )
                return i + 1;
        }

        return 0;
    }

    auto hasFinalizer() const { return field("~finally") != nullptr; }

    hilti::node::Set<type::function::Parameter> parameters() const final {
        return childrenOfType<type::function::Parameter>();
    }

    void addField(ASTContext* ctx, Declaration* f) {
        assert(f->isA<declaration::Field>());
        addChild(ctx, f);
    }

    std::string_view typeClass() const final { return "union"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isNameType() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final;

    static auto create(ASTContext* ctx, const declaration::Parameters& params, Declarations fields, Meta meta = {}) {
        for ( auto&& p : params )
            p->setIsTypeParameter();

        return ctx->make<Union>(ctx, node::flatten(params, std::move(fields)), -1, std::move(meta));
    }

    static auto create(ASTContext* ctx, const Declarations& fields, Meta meta = {}) {
        return create(ctx, declaration::Parameters{}, fields, std::move(meta));
    }

    union AnonymousUnion {};
    static auto create(ASTContext* ctx, AnonymousUnion _, Declarations fields, Meta meta = {}) {
        return ctx->make<Union>(ctx, std::move(fields), ++anon_union_counter, std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, Meta meta = {}) {
        return ctx->make<Union>(ctx, Wildcard(), std::move(meta));
    }

protected:
    Union(ASTContext* ctx, const Nodes& children, int64_t anon_union, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, children, std::move(meta)), _anon_union(anon_union) {}

    Union(ASTContext* ctx, Wildcard _, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"union(*)"}, std::move(meta)) {}

    HILTI_NODE_1(type::Union, UnqualifiedType, final);

private:
    int64_t _anon_union = -1;

    static int64_t anon_union_counter;
};

} // namespace hilti::type
