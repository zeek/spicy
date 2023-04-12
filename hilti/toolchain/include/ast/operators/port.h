// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <vector>

#include <hilti/ast/builder/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/port.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_2(port, Equal, type::Bool(), type::Port(), type::Port(), "Compares two port values.")
STANDARD_OPERATOR_2(port, Unequal, type::Bool(), type::Port(), type::Port(), "Compares two port values.")

BEGIN_KEYWORD_CTOR(port, Ctor, "port", type::Port(), "Creates a port instance.")
    std::vector<Operand> parameters() const {
        return {{"port", hilti::type::UnsignedInteger(16)}, {"protocol", type::Enum(type::Wildcard())}};
    }
END_KEYWORD_CTOR

BEGIN_METHOD(port, Protocol)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Port(),
                                           .result = builder::typeByID("hilti::Protocol"),
                                           .id = "protocol",
                                           .args = {},
                                           .doc = R"(
Returns the protocol the port is using (such as UDP or TCP).
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
