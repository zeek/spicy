// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/list.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace list {

namespace iterator {
class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeListIterator(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "list::iterator",
            .doc = "Returns the list element that the iterator refers to.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Optional>()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, list::iterator::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);


class IncrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPostfix,
            .op0 = {parameter::Kind::InOut, builder->typeListIterator(type::Wildcard())},
            .result_doc = "iterator<list<*>>",
            .ns = "list::iterator",
            .doc = "Advances the iterator by one list element, returning the previous position.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, list::iterator::IncrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPostfix);


class IncrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPrefix,
            .op0 = {parameter::Kind::InOut, builder->typeListIterator(type::Wildcard())},
            .result_doc = "iterator<list<*>>",
            .ns = "list::iterator",
            .doc = "Advances the iterator by one list element, returning the new position.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, list::iterator::IncrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPrefix);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeListIterator(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeListIterator(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "list::iterator",
            .doc = "Returns true if two lists iterators refer to the same location.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, list::iterator::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeListIterator(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeListIterator(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "list::iterator",
            .doc = "Returns true if two lists iterators refer to different locations.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, list::iterator::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);
} // namespace iterator

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Size,
            .op0 = {parameter::Kind::In, builder->typeList(type::Wildcard())},
            .result = {Constness::Const, builder->typeUnsignedInteger(64)},
            .ns = "list",
            .doc = "Returns the number of elements a list contains.",
        };
    }

    HILTI_OPERATOR(hilti, list::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeList(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeList(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "list",
            .doc = "Compares two lists element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, list::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeList(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeList(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "list",
            .doc = "Compares two lists element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, list::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

} // namespace list
} // namespace
