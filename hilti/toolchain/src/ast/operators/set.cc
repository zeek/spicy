// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/set.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace set {

namespace iterator {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeSetIterator(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "set::iterator",
            .doc = "Returns the set element that the iterator refers to.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, set::iterator::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class IncrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPostfix,
            .op0 = {parameter::Kind::InOut, builder->typeSetIterator(type::Wildcard())},
            .result_doc = "iterator<set<*>>",
            .ns = "set::iterator",
            .doc = "Advances the iterator by one set element, returning the previous position.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, set::iterator::IncrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPostfix);

class IncrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPrefix,
            .op0 = {parameter::Kind::InOut, builder->typeSetIterator(type::Wildcard())},
            .result_doc = "iterator<set<*>>",
            .ns = "set::iterator",
            .doc = "Advances the iterator by one set element, returning the new position.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }


    HILTI_OPERATOR(hilti, set::iterator::IncrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPrefix);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeSetIterator(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSetIterator(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "set::iterator",
            .doc = "Returns true if two sets iterators refer to the same location.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, set::iterator::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeSetIterator(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSetIterator(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "set::iterator",
            .doc = "Returns true if two sets iterators refer to different locations.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, set::iterator::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

} // namespace iterator

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Size,
            .op0 = {parameter::Kind::In, builder->typeSet(type::Wildcard())},
            .result = {Constness::Const, builder->typeUnsignedInteger(64)},
            .ns = "set",
            .doc = "Returns the number of elements a set contains.",
        };
    }

    HILTI_OPERATOR(hilti, set::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeSet(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSet(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "set",
            .doc = "Compares two sets element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, set::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeSet(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeSet(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "set",
            .doc = "Compares two sets element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, set::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class In : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::In,
            .op0 = {parameter::Kind::In, builder->typeAny()},
            .op1 = {parameter::Kind::In, builder->typeSet(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "set",
            .doc = "Returns true if an element is part of the set.",
        };
    }

    HILTI_OPERATOR(hilti, set::In)
};
HILTI_OPERATOR_IMPLEMENTATION(In);

class Add : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Add,
            .op0 = {parameter::Kind::InOut, builder->typeSet(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeAny(), "element"},
            .result = {Constness::Const, builder->typeVoid()},
            .ns = "set",
            .doc = "Adds an element to the set.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto op1 = operandForType(builder, parameter::Kind::In,
                                  operands[0]->type()->type()->as<type::Set>()->elementType()->type());
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, set::Add)
};
HILTI_OPERATOR_IMPLEMENTATION(Add)

class Delete : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Delete,
            .op0 = {parameter::Kind::InOut, builder->typeSet(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeAny(), "element"},
            .result = {Constness::Const, builder->typeVoid()},
            .ns = "set",
            .doc = "Removes an element from the set.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto op1 = operandForType(builder, parameter::Kind::In,
                                  operands[0]->type()->type()->as<type::Set>()->elementType()->type());
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, set::Delete)
};
HILTI_OPERATOR_IMPLEMENTATION(Delete)

class Clear : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::InOut, builder->typeSet(type::Wildcard())},
            .member = "clear",
            .result = {Constness::Const, builder->typeVoid()},
            .ns = "set",
            .doc = R"(
Removes all elements from the set.
)",
        };
    }

    HILTI_OPERATOR(hilti, set::Clear);
};
HILTI_OPERATOR_IMPLEMENTATION(Clear);

} // namespace set
} // namespace
