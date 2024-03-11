// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace reference {

namespace strong_reference {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeStrongReference(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "strong_reference",
            .doc = "Returns the referenced instance, or throws an exception if none or expired.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::StrongReference>()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, strong_reference::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeStrongReference(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeStrongReference(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "strong_reference",
            .doc = "Returns true if both operands reference the same instance.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, strong_reference::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeStrongReference(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeStrongReference(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "strong_reference",
            .doc = "Returns true if the two operands reference different instances.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, strong_reference::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

} // namespace strong_reference

namespace weak_reference {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeWeakReference(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "weak_reference",
            .doc = "Returns the referenced instance, or throws an exception if none or expired.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::WeakReference>()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, weak_reference::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeWeakReference(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeWeakReference(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "weak_reference",
            .doc = "Returns true if both operands reference the same instance.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, weak_reference::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeWeakReference(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeWeakReference(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "weak_reference",
            .doc = "Returns true if the two operands reference different instances.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, weak_reference::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

} // namespace weak_reference

namespace value_reference {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeValueReference(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "value_reference",
            .doc = "Returns the referenced instance, or throws an exception if none or expired.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::ValueReference>()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, value_reference::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeValueReference(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeValueReference(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "value_reference",
            .doc = "Returns true if the values of both operands are equal.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, value_reference::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal)

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeValueReference(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeValueReference(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "value_reference",
            .doc = "Returns true if the values of both operands are not equal.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, value_reference::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal)

} // namespace value_reference

} // namespace reference
} // namespace
