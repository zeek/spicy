// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/builder/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/address.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_2(address, Equal, type::Bool(), type::Address(), type::Address(), "Compares two address values.")
STANDARD_OPERATOR_2(address, Unequal, type::Bool(), type::Address(), type::Address(), "Compares two address values.")

BEGIN_METHOD(address, Family)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Address(),
                                           .result = builder::typeByID("hilti::AddressFamily"),
                                           .id = "family",
                                           .args = {},
                                           .doc = R"(
Returns the protocol family of the address, which can be IPv4 or IPv6.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
