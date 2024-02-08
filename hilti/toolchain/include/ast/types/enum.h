// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>

namespace hilti::type {

class Enum;

namespace enum_ {

/** AST node for an enum label. */
class Label final : public Node {
public:
    ~Label() final;

    const ID& id() const { return _id; }
    auto value() const { return _value; }
    auto enumType() const { return child<QualifiedType>(0)->type(); }

    node::Properties properties() const final {
        auto p = node::Properties{{"id", _id}, {"value", _value}};
        return Node::properties() + p;
    }

    static auto create(ASTContext* ctx, const ID& id, int value, const Meta& meta = {}) {
        return std::shared_ptr<Label>(new Label(ctx, {nullptr}, id, value, meta));
    }

    static auto create(ASTContext* ctx, const ID& id, const Meta& meta = {}) {
        return std::shared_ptr<Label>(new Label(ctx, {nullptr}, id, -1, meta));
    }

protected:
    friend class type::Enum;

    Label(ASTContext* ctx, Nodes children, ID id, int value, Meta meta = {})
        : Node(ctx, std::move(children), std::move(meta)), _id(std::move(id)), _value(value) {}

    void setValue(int value) { _value = value; }
    void setEnumType(ASTContext* ctx, const QualifiedTypePtr& type) { setChild(ctx, 0, type); }

    HILTI_NODE(hilti, Label)

private:
    ID _id;
    int _value = -1;
};

using LabelPtr = std::shared_ptr<Label>;
using Labels = std::vector<LabelPtr>;

} // namespace enum_

/** AST node for a `enum` type. */
class Enum : public UnqualifiedType {
public:
    enum_::Labels labels() const;
    auto labelDeclarations() const { return children<Declaration>(0, {}); }

    /**
     * Filters a set of labels so that it includes each enumerator value at
     * most once.
     */
    enum_::Labels uniqueLabels() const;

    enum_::LabelPtr label(const ID& id) const {
        for ( const auto& l : labels() ) {
            if ( l->id() == id )
                return l;
        }

        return {};
    }

    std::string_view typeClass() const final { return "enum"; }

    bool isAllocable() const final { return true; }
    bool isSortable() const final { return true; }
    bool isNameType() const final { return true; }

    static auto create(ASTContext* ctx, enum_::Labels labels, Meta meta = {}) {
        auto t = std::shared_ptr<Enum>(new Enum(ctx, {}, std::move(meta)));
        t->_setLabels(ctx, std::move(labels));
        return t;
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return std::shared_ptr<Enum>(new Enum(ctx, Wildcard(), m));
    }

protected:
    Enum(ASTContext* ctx, Nodes children, Meta meta) : UnqualifiedType(ctx, {}, std::move(children), std::move(meta)) {}
    Enum(ASTContext* ctx, Wildcard _, const Meta& meta) : UnqualifiedType(ctx, Wildcard(), {"enum(*)"}, meta) {}

    HILTI_NODE(hilti, Enum)

private:
    void _setLabels(ASTContext* ctx, enum_::Labels labels);
};

} // namespace hilti::type
