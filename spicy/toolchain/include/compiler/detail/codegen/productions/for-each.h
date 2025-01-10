// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/** A production executing until interrupted by a foreach hook. */
class ForEach : public Production {
public:
    ForEach(ASTContext* /* ctx */, const std::string& symbol, std::unique_ptr<Production> body, bool eod_ok,
            const Location& l = location::None)
        : Production(symbol, l), _body(std::move(body)), _eod_ok(eod_ok) {}

    const auto* body() const { return _body.get(); }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final { return _eod_ok ? _eod_ok : isNullable(); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };

    std::vector<std::vector<Production*>> rhss() const final { return {{_body.get()}}; };

    std::string dump() const override { return hilti::util::fmt("foreach: %s", _body->symbol()); }

    SPICY_PRODUCTION

private:
    std::unique_ptr<Production> _body;
    bool _eod_ok;
};

} // namespace spicy::detail::codegen::production
