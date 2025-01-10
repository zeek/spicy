// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/expressions/ctor.h>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/** A literal represented by a ctor. */
class Ctor : public Production {
public:
    Ctor(ASTContext* ctx, const std::string& symbol, hilti::Ctor* ctor, const Location& l = location::None)
        : Production(symbol, l), _ctor(hilti::expression::Ctor::create(ctx, ctor)) {
        assert(_ctor->isA<hilti::expression::Ctor>());
    }

    auto ctor() const { return _ctor->as<hilti::expression::Ctor>()->ctor(); };

    bool isAtomic() const final { return true; };
    bool isEodOk() const final { return false; };
    bool isLiteral() const final { return true; };
    bool isNullable() const final { return false; };
    bool isTerminal() const final { return true; };

    // std::vector<std::vector<Production*>> rhss() const final { return {}; };
    Expression* expression() const final { return _ctor; }
    QualifiedType* type() const final { return _ctor->type(); };

    int64_t tokenID() const final {
        return static_cast<int64_t>(Production::tokenID(hilti::util::fmt("%s|%s", *_ctor, *_ctor->type())));
    }

    std::string dump() const final { return hilti::util::fmt("%s (%s)", *_ctor, *_ctor->type()); }

    SPICY_PRODUCTION

private:
    Expression* _ctor = nullptr;
};

} // namespace spicy::detail::codegen::production
