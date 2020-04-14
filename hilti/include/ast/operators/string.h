// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/string.h>

namespace hilti {
namespace operator_ {

STANDARD_OPERATOR_2(string, Equal, type::Bool(), type::String(), type::String(),
                    "Compares two strings lexicographically.")
STANDARD_OPERATOR_2(string, Unequal, type::Bool(), type::String(), type::String(),
                    "Compares two strings lexicographically.")
STANDARD_OPERATOR_1(string, Size, type::UnsignedInteger(64), type::String(),
                    "Returns the number of characters the string contains.");
STANDARD_OPERATOR_2(string, Sum, type::String(), type::String(), type::String(),
                    "Returns the concatentation of two strings.");

BEGIN_OPERATOR_CUSTOM(string, Modulo)
    Type result(const std::vector<Expression>& /* ops */) const { return type::String(); }

    bool isLhs() const { return false; }

    std::vector<Operand> operands() const { return {{.type = type::String()}, {.type = type::Any()}}; }

    void validate(const expression::ResolvedOperator& /* i */, operator_::position_t /* p */) const {
        // TODO(robin): Not sure if we need this restriction. Let's try without.
        //
        // if ( i.op1().type().isA<type::Tuple>() && ! i.op1().isA<expression::Ctor>() )
        //    p.node.setError("tuple argument to '%' must a be constant");
    }

    std::string doc() const { return "Renders a printf-style format string."; }
END_OPERATOR_CUSTOM

} // namespace operator_
} // namespace hilti
