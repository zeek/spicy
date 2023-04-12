// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/type.h>

namespace hilti::type {

/**
 * AST node for a type representing a list of function/method operands. This
 * is an internal type used for overload resolution, it's nothing actually
 * instantiated by a HILTI program. That's also why we don't use any child
 * nodes, but store the operands directly.
 */
class OperandList : public TypeBase {
public:
    OperandList(std::vector<operator_::Operand> operands) : _operands(std::move(operands)) {}

    const auto& operands() const { return _operands; }

    /** Implements the `Type` interface. */
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const OperandList& other) const { return operands() == other.operands(); }

    template<typename Container>
    static OperandList fromParameters(const Container& params) {
        std::vector<operator_::Operand> ops;

        for ( const auto& p : params ) {
            operator_::Operand op = {p.id(), (p.isConstant() ? type::constant(p.type()) : p.type()),
                                     p.default_().has_value(), p.default_()};

            ops.push_back(std::move(op));
        }

        return type::OperandList(std::move(ops));
    }

private:
    std::vector<operator_::Operand> _operands;
};

} // namespace hilti::type
