// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
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

    declaration::FieldPtr field(const ID& id) const {
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

    void addField(ASTContext* ctx, DeclarationPtr f) {
        assert(f->isA<declaration::Field>());
        addChild(ctx, std::move(f));
    }

    std::string_view typeClass() const final { return "union"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isNameType() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final;

    static auto create(ASTContext* ctx, const declaration::Parameters& params, Declarations fields,
                       const Meta& meta = {}) {
        for ( auto&& p : params )
            p->setIsTypeParameter();

        return std::shared_ptr<Union>(new Union(ctx, node::flatten(params, std::move(fields)), -1, meta));
    }

    static auto create(ASTContext* ctx, const Declarations& fields, const Meta& meta = {}) {
        return create(ctx, declaration::Parameters{}, fields, meta);
    }

    union AnonymousUnion {};
    static auto create(ASTContext* ctx, AnonymousUnion _, Declarations fields, const Meta& meta = {}) {
        return std::shared_ptr<Union>(new Union(ctx, std::move(fields), ++anon_union_counter, meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& meta = {}) {
        return std::shared_ptr<Union>(new Union(ctx, Wildcard(), meta));
    }

protected:
    Union(ASTContext* ctx, const Nodes& children, int64_t anon_union, const Meta& meta)
        : UnqualifiedType(ctx, {}, children, meta), _anon_union(anon_union) {}

    Union(ASTContext* ctx, Wildcard _, const Meta& meta) : UnqualifiedType(ctx, Wildcard(), {"union(*)"}, meta) {}

    HILTI_NODE(hilti, Union)

private:
    int64_t _anon_union = -1;

    static int64_t anon_union_counter;
};

} // namespace hilti::type
