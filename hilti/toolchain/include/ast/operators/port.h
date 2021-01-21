// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/builder/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/port.h>

namespace hilti {
namespace operator_ {

STANDARD_OPERATOR_2(port, Equal, type::Bool(), type::Port(), type::Port(), "Compares two port values.")
STANDARD_OPERATOR_2(port, Unequal, type::Bool(), type::Port(), type::Port(), "Compares two port values.")

BEGIN_METHOD(port, Protocol)
    auto signature() const {
        return Signature{.self = type::Port(),
                         .result = builder::typeByID("hilti::Protocol"),
                         .id = "protocol",
                         .args = {},
                         .doc = R"(
Returns the protocol the port is using (such as UDP or TCP).
)"};
    }
END_METHOD

} // namespace operator_
} // namespace hilti
