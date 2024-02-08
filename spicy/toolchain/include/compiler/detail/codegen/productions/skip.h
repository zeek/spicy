// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/attribute.h>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/** A production simply skipping input data. */
class Skip : public Production {
public:
    Skip(ASTContext* ctx, const std::string& symbol, type::unit::item::FieldPtr field, std::unique_ptr<Production> ctor,
         const Location& l = location::None)
        : Production(symbol, l),
          _field(std::move(field)),
          _ctor(std::move(ctor)),
          _void(QualifiedType::create(ctx, hilti::type::Void::create(ctx), hilti::Constness::Const)) {}

    const auto& field() const { return _field; }
    const auto& ctor() const { return _ctor; }

    bool isAtomic() const final { return true; };
    bool isEodOk() const final { return _field->attributes()->has("&eod"); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return false; };
    bool isTerminal() const final { return true; };

    QualifiedTypePtr type() const final { return _void; };

    std::string dump() const override {
        return hilti::util::fmt("skip: %s", _ctor ? to_string(*_ctor) : _field->print());
    }

    SPICY_PRODUCTION

private:
    type::unit::item::FieldPtr _field; // stores a shallow copy of the reference passed into ctor
    std::unique_ptr<Production> _ctor;
    QualifiedTypePtr _void;
};

} // namespace spicy::detail::codegen::production
