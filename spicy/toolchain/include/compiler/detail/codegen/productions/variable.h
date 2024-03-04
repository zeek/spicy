// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/**
 * A variable. A variable is a terminal that will be parsed from the input
 * stream according to its type, yet is not recognizable as such in advance
 * by just looking at the available bytes. If we start parsing, we assume it
 * will match (and if not, generate a parse error).
 */
class Variable : public Production {
public:
    Variable(ASTContext* /* ctx */, const std::string& symbol, QualifiedTypePtr type,
             const Location& l = location::None)
        : Production(symbol, l), _type(std::move(type)) {}

    bool isAtomic() const final { return true; };
    bool isEodOk() const final { return false; };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return false; };
    bool isTerminal() const final { return true; };

    QualifiedTypePtr type() const final { return _type; };

    std::string dump() const final { return hilti::util::fmt("%s", *_type); }

    SPICY_PRODUCTION

private:
    QualifiedTypePtr _type;
};

} // namespace spicy::detail::codegen::production
