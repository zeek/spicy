// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/address.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace address {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeAddress()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeAddress()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "address",
            .doc = "Compares two address values.",
        };
    }

    HILTI_OPERATOR(hilti, address::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeAddress()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeAddress()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "address",
            .doc = "Compares two address values.",
        };
    }

    HILTI_OPERATOR(hilti, address::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

class Family : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeAddress()},
            .member = "family",
            .result = {.constness = Constness::Const, .type = builder->typeName("hilti::AddressFamily")},
            .ns = "address",
            .doc = R"(
Returns the protocol family of the address, which can be IPv4 or IPv6.
)",
        };
    }

    HILTI_OPERATOR(hilti, address::Family);
};
HILTI_OPERATOR_IMPLEMENTATION(Family)

} // namespace address
} // namespace
