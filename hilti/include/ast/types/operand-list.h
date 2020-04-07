// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/type.h>

namespace hilti {
namespace type {

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
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    bool operator==(const OperandList& other) const { return operands() == other.operands(); }

    static OperandList fromParameters(const std::vector<declaration::Parameter>& params) {
        std::vector<operator_::Operand> ops;

        for ( const auto& p : params ) {
            operator_::Operand op = {.id = p.id(),
                                     .type = type::setConstant(p.type(), p.isConstant()),
                                     .optional = p.default_().has_value(),
                                     .default_ = p.default_()};

            ops.push_back(std::move(op));
        }

        return type::OperandList(std::move(ops));
    }

private:
    std::vector<operator_::Operand> _operands;
};

} // namespace type
} // namespace hilti
