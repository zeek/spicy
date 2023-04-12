// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/string.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_2(string, Equal, type::Bool(), type::String(), type::String(),
                    "Compares two strings lexicographically.")
STANDARD_OPERATOR_2(string, Unequal, type::Bool(), type::String(), type::String(),
                    "Compares two strings lexicographically.")
STANDARD_OPERATOR_1(string, Size, type::UnsignedInteger(64), type::String(),
                    "Returns the number of characters the string contains.");
STANDARD_OPERATOR_2(string, Sum, type::String(), type::String(), type::String(),
                    "Returns the concatenation of two strings.");

BEGIN_METHOD(string, Encode)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::constant(type::String()),
                      .result = type::Bytes(),
                      .id = "encode",
                      .args = {{"charset", type::Enum(type::Wildcard()), false, builder::id("hilti::Charset::UTF8")}},
                      .doc =
                          R"(
Converts the string into a binary representation encoded with the given character set.
)"};
        return _signature;
    }
END_METHOD

BEGIN_OPERATOR_CUSTOM(string, Modulo)
    Type result(const hilti::node::Range<Expression>& /* ops */) const { return type::String(); }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {{{}, type::String()}, {{}, type::Any()}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& /* i */, operator_::position_t /* p */) const {
        // TODO(robin): Not sure if we need this restriction. Let's try without.
        //
        // if ( i.op1().type().isA<type::Tuple>() && ! i.op1().isA<expression::Ctor>() )
        //    p.node.addError("tuple argument to '%' must a be constant");
    }

    std::string doc() const { return "Renders a printf-style format string."; }
END_OPERATOR_CUSTOM

} // namespace hilti::operator_
