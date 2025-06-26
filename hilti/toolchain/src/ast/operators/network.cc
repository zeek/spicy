// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/network.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace network {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeNetwork()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeNetwork()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "network",
            .doc = "Compares two network values.",
        };
    }

    HILTI_OPERATOR(hilti, network::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeNetwork()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeNetwork()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "network",
            .doc = "Compares two network values.",
        };
    }

    HILTI_OPERATOR(hilti, network::Unequal)
};

HILTI_OPERATOR_IMPLEMENTATION(Unequal)
class In : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::In,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeAddress()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeNetwork()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "network",
            .doc = "Returns true if the address is part of the network range.",
        };
    }

    HILTI_OPERATOR(hilti, network::In)
};
HILTI_OPERATOR_IMPLEMENTATION(In)

class Family : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeNetwork()},
            .member = "family",
            .result = {.constness = Constness::Const, .type = builder->typeName("hilti::AddressFamily")},
            .ns = "network",
            .doc = R"(
Returns the protocol family of the network, which can be IPv4 or IPv6.
)",
        };
    }

    HILTI_OPERATOR(hilti, network::Family);
};
HILTI_OPERATOR_IMPLEMENTATION(Family);

class Prefix : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeNetwork()},
            .member = "prefix",
            .result = {.constness = Constness::Const, .type = builder->typeAddress()},
            .ns = "network",
            .doc = R"(
Returns the network's prefix as a masked IP address.
)",
        };
    }

    HILTI_OPERATOR(hilti, network::Prefix);
};
HILTI_OPERATOR_IMPLEMENTATION(Prefix);

class Length : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeNetwork()},
            .member = "length",
            .result = {.constness = Constness::Const, .type = builder->typeSignedInteger(64)},
            .ns = "network",
            .doc = R"(
Returns the length of the network's prefix.
)",
        };
    }

    HILTI_OPERATOR(hilti, network::Length);
};
HILTI_OPERATOR_IMPLEMENTATION(Length);

} // namespace network
} // namespace
