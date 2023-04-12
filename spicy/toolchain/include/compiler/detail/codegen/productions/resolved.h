// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>

#include <spicy/compiler/detail/codegen/production.h>

namespace spicy::detail::codegen {
class Grammar;
} // namespace spicy::detail::codegen

namespace spicy::detail::codegen::production {

/*
 * Place-holder production that's resolved through a `Grammar` later. This
 * can used to be create to self-recursive grammars.
 *
 * @note This option doesn't actually implement most of the `Production` API
 * (meaniningfully).
 */
class Resolved : public ProductionBase {
public:
    Resolved(const Location& l = location::None)
        : ProductionBase("", l),
          _symbol(std::make_shared<std::string>("<unresolved>")),
          _rsymbol(hilti::util::fmt("ref:%d", ++_cnt)) {}
    std::string render() const { return symbol(); }

    const std::string& symbol() const { return *_symbol; }
    const std::string& referencedSymbol() const { return _rsymbol; }

    void resolve(const std::string& symbol) { *_symbol = symbol; }

    // Production API methods are meaningless for this one.
    bool nullable() const { return false; }
    bool eodOk() const { return false; }
    bool atomic() const { return true; }
    std::optional<spicy::Type> type() const { return {}; }


    std::shared_ptr<std::string> _symbol;
    std::string _rsymbol;

    inline static int _cnt = 0;
};

// Alias the name for clarity. The idea is that initiallu one creates
// `Unresolved` instances. Once they have been resolved, one then operates on
// `Resolved` instances. Internally, however, the two are the same.
using Unresolved = Resolved;

} // namespace spicy::detail::codegen::production
