// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>

using namespace hilti;
using namespace hilti::operator_;
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/port.h>

namespace {
namespace port {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typePort()},
            .op1 = {parameter::Kind::In, builder->typePort()},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "port",
            .doc = "Compares two port values.",
        };
    }

    HILTI_OPERATOR(hilti, port::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typePort()},
            .op1 = {parameter::Kind::In, builder->typePort()},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "port",
            .doc = "Compares two port values.",
        };
    }

    HILTI_OPERATOR(hilti, port::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

class Ctor : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "port",
            .param0 = {.name = "port", .type = {parameter::Kind::In, builder->typeUnsignedInteger(16)}},
            .param1 = {.name = "protocol", .type = {parameter::Kind::In, builder->typeName("hilti::Protocol")}},
            .result = {Constness::Const, builder->typePort()},
            .ns = "port",
            .doc = "Creates a port instance.",
        };
    }
    HILTI_OPERATOR(hilti, port::Ctor)
};
HILTI_OPERATOR_IMPLEMENTATION(Ctor)

class Protocol : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typePort()},
            .member = "protocol",
            .result = {Constness::Const, builder->typeName("hilti::Protocol")},
            .ns = "port",
            .doc = R"(
Returns the protocol the port is using (such as UDP or TCP).
)",
        };
    }

    HILTI_OPERATOR(hilti, port::Protocol);
};
HILTI_OPERATOR_IMPLEMENTATION(Protocol)

} // namespace port
} // namespace
