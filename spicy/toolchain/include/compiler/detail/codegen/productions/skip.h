// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/attribute.h>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/** A production simply skipping input data. */
class Skip : public Production {
public:
    Skip(ASTContext* ctx, const std::string& symbol, type::unit::item::Field* field, std::unique_ptr<Production> ctor,
         const Location& l = location::None)
        : Production(symbol, l),
          _field(field),
          _ctor(std::move(ctor)),
          _void(QualifiedType::create(ctx, hilti::type::Void::create(ctx), hilti::Constness::Const)) {
        auto m = meta();
        m.setField(field, true);
        setMeta(m);
    }

    const auto& field() const { return _field; }
    const auto& ctor() const { return _ctor; }

    bool isAtomic() const final { return _ctor ? _ctor->isAtomic() : true; };
    bool isEodOk() const final {
        return _ctor ? _ctor->isEodOk() : _field->attributes()->has(hilti::attribute::Kind::Eod);
    };
    bool isLiteral() const final { return _ctor ? _ctor->isLiteral() : false; };
    bool isNullable() const final { return _ctor ? _ctor->isNullable() : false; };
    bool isTerminal() const final { return _ctor ? _ctor->isTerminal() : true; };
    int64_t tokenID() const final { return _ctor ? _ctor->tokenID() : -1; };

    std::vector<std::vector<Production*>> rhss() const final {
        if ( _ctor )
            return _ctor->rhss();
        else
            return {};
    };


    Expression* expression() const final { return _ctor ? _ctor->expression() : nullptr; }

    QualifiedType* type() const final { return _void; };

    std::string dump() const override {
        return hilti::util::fmt("skip: %s", _ctor ? to_string(*_ctor) : _field->print());
    }

    SPICY_PRODUCTION

private:
    type::unit::item::Field* _field = nullptr; // stores a shallow copy of the reference passed into ctor
    std::unique_ptr<Production> _ctor;
    QualifiedType* _void = nullptr;
};

} // namespace spicy::detail::codegen::production
