// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/function.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>
#include <hilti/ast/types/name.h>
#include <hilti/ast/types/reference.h>

namespace hilti::type {

/** AST node for a `struct` type. */
class Struct : public UnqualifiedType {
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

    auto hasFinalizer() const { return field("~finally") != nullptr; }

    auto self() const {
        assert(! isWildcard());
        return child<declaration::Expression>(0);
    }

    hilti::node::Set<type::function::Parameter> parameters() const final {
        return childrenOfType<type::function::Parameter>();
    }

    void addField(ASTContext* ctx, DeclarationPtr f) {
        assert(f->isA<declaration::Field>());
        addChild(ctx, std::move(f));
    }

    std::string_view typeClass() const final { return "struct"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }
    bool isNameType() const final { return true; }
    bool isResolved(node::CycleDetector* cd) const final;

    static auto create(ASTContext* ctx, const declaration::Parameters& params, Declarations fields,
                       const Meta& meta = {}) {
        for ( auto&& p : params )
            p->setIsTypeParameter();

        auto t = std::shared_ptr<Struct>(new Struct(ctx, node::flatten(NodePtr(), params, std::move(fields)), meta));
        t->_setSelf(ctx);
        return t;
    }

    static auto create(ASTContext* ctx, const Declarations& fields, const Meta& meta = {}) {
        auto t = create(ctx, declaration::Parameters{}, fields, meta);
        t->_setSelf(ctx);
        return t;
    }

    struct AnonymousStruct {};
    static auto create(ASTContext* ctx, AnonymousStruct _, Declarations fields, const Meta& meta = {}) {
        auto t = std::shared_ptr<Struct>(new Struct(ctx, node::flatten(nullptr, std::move(fields)), meta));
        t->_setSelf(ctx);
        return t;
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& meta = {}) {
        return std::shared_ptr<Struct>(new Struct(ctx, Wildcard(), {nullptr}, meta));
    }

protected:
    Struct(ASTContext* ctx, const Nodes& children, const Meta& meta) : UnqualifiedType(ctx, {}, children, meta) {}

    Struct(ASTContext* ctx, Wildcard _, const Nodes& children, Meta meta)
        : UnqualifiedType(ctx, Wildcard(), {"struct(*)"}, children, std::move(meta)) {}

    HILTI_NODE(hilti, Struct)

private:
    void _setSelf(ASTContext* ctx);
};

using StructPtr = std::shared_ptr<Struct>;

} // namespace hilti::type
