// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/builder/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/network.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_2(network, Equal, type::Bool(), type::Network(), type::Network(), "Compares two network values.")
STANDARD_OPERATOR_2(network, Unequal, type::Bool(), type::Network(), type::Network(), "Compares two network values.")
STANDARD_OPERATOR_2(network, In, type::Bool(), type::Address(), type::Network(),
                    "Returns true if the address is part of the network range.")

BEGIN_METHOD(network, Family)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Network(),
                                           .result = builder::typeByID("hilti::AddressFamily"),
                                           .id = "family",
                                           .args = {},
                                           .doc = R"(
Returns the protocol family of the network, which can be IPv4 or IPv6.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(network, Prefix)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::Network(), .result = type::Address(), .id = "prefix", .args = {}, .doc = R"(
Returns the network's prefix as a masked IP address.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(network, Length)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::Network(), .result = type::SignedInteger(64), .id = "length", .args = {}, .doc = R"(
Returns the length of the network's prefix.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
