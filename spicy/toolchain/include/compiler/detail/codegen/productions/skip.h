// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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
    Skip(ASTContext* ctx, const std::string& symbol, std::unique_ptr<Production> production,
         const Location& l = location::None)
        : Production(symbol, l),
          _production(std::move(production)),
          _void(QualifiedType::create(ctx, hilti::type::Void::create(ctx), hilti::Constness::Const)) {
        assert(_production);
        setMeta(_production->meta());
    }

    const auto& production() const { return _production; }

    bool isAtomic() const final { return _production->isAtomic(); };
    bool isEodOk() const final { return _production->isEodOk(); };
    bool isLiteral() const final { return _production->isLiteral(); };
    bool isNullable() const final { return _production->isNullable(); };
    bool isTerminal() const final { return _production->isTerminal(); };
    int64_t tokenID() const final { return _production->tokenID(); };

    std::vector<std::vector<Production*>> rhss() const final { return _production->rhss(); };

    Expression* expression() const final { return _production->expression(); }

    QualifiedType* type() const final { return _void; };

    Expression* _bytesConsumed(ASTContext* context) const final { return _production->bytesConsumed(context); }

    std::string dump() const override { return hilti::util::fmt("skip: %s", _production->print()); }

    SPICY_PRODUCTION

private:
    std::unique_ptr<Production> _production;
    QualifiedType* _void = nullptr;
};

} // namespace spicy::detail::codegen::production
