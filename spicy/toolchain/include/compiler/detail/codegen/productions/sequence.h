// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/base/util.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/codegen/production.h>
#include <spicy/compiler/detail/codegen/productions/visitor.h>

namespace spicy::detail::codegen::production {

/** * A production representing a sequence of other sub-productions to be parsed sequentially. */
class Sequence : public Production {
public:
    Sequence(ASTContext* /* ctx */, const std::string& symbol, std::vector<std::unique_ptr<Production>> prods,
             const Location& l = location::None)
        : Production(symbol, l), _prods(std::move(prods)) {}

    const auto& sequence() const { return _prods; }
    void add(std::unique_ptr<Production> p) { _prods.push_back(std::move(p)); }

    bool isAtomic() const final { return false; };
    bool isEodOk() const final { return isNullable(); };
    bool isLiteral() const final { return false; };
    bool isNullable() const final { return production::isNullable(rhss()); };
    bool isTerminal() const final { return false; };

    std::vector<std::vector<Production*>> rhss() const final {
        return {hilti::util::transform(_prods, [](const auto& p) { return p.get(); })};
    }

    Expression* _bytesConsumed(ASTContext* context) const final {
        Expression* size = nullptr;
        for ( const auto& p : _prods ) {
            auto* psize = p->bytesConsumed(context);
            if ( ! psize )
                return nullptr;

            if ( ! size )
                size = psize;
            else
                size =
                    hilti::expression::UnresolvedOperator::create(context, hilti::operator_::Kind::Sum, {size, psize});
        }

        return size;
    }

    std::string dump() const final {
        return hilti::util::join(hilti::util::transform(_prods, [](const auto& p) { return p->symbol(); }), " ");
    }

    SPICY_PRODUCTION

private:
    std::vector<std::unique_ptr<Production>> _prods;
};

} // namespace spicy::detail::codegen::production
