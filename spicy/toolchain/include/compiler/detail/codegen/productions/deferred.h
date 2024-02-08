// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen {
class Grammar;
} // namespace spicy::detail::codegen

namespace spicy::detail::codegen::production {

/*
 * Place-holder production that's resolved through a `Grammar` later. This
 * can used to be create to self-recursive grammars.
 *
 * @note This option doesn't actually implement most of the `Production` API
 * (meaningfully).
 */
class Deferred : public Production {
public:
    Deferred(ASTContext* /* ctx */, const Location& l = location::None)
        : Production(hilti::util::fmt("Resolved_%d", ++_cnt), l) {}

    void resolve(Production* p) { _resolved = p; }

    auto resolved() const { return _resolved; }

    bool isAtomic() const final { return true; }
    bool isEodOk() const final { return false; }
    bool isLiteral() const final { return false; }
    bool isNullable() const final { return false; }
    bool isTerminal() const final { return false; }
    int64_t tokenID() const final { return _resolved ? _resolved->tokenID() : -1; };

    std::string dump() const final {
        if ( _resolved )
            return _resolved->symbol();
        else
            return "<unresolved>";
    }

    SPICY_PRODUCTION

private:
    Production* _resolved = nullptr;

    inline static int _cnt = 0;
};

} // namespace spicy::detail::codegen::production
