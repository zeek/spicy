// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/string.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace bool_ {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "bool_",
            .doc = "Compares two boolean values.",
        };
    }

    HILTI_OPERATOR(hilti, bool_::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "bool_",
            .doc = "Compares two boolean values.",
        };
    }

    HILTI_OPERATOR(hilti, bool_::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

class BitAnd : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::BitAnd,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "bool_",
            .doc = "Computes the bit-wise 'and' of the two boolean values.",
        };
    }

    HILTI_OPERATOR(hilti, bool_::BitAnd)
};
HILTI_OPERATOR_IMPLEMENTATION(BitAnd);

class BitOr : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::BitOr,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "bool_",
            .doc = "Computes the bit-wise 'or' of the two boolean values.",
        };
    }

    HILTI_OPERATOR(hilti, bool_::BitOr)
};
HILTI_OPERATOR_IMPLEMENTATION(BitOr);

class BitXor : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::BitXor,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBool()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "bool_",
            .doc = "Computes the bit-wise 'xor' of the two boolean values.",
        };
    }

    HILTI_OPERATOR(hilti, bool_::BitXor)
};
HILTI_OPERATOR_IMPLEMENTATION(BitXor);

} // namespace bool_
} // namespace
