// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/map.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace map {

namespace iterator {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeMapIterator(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "map::iterator",
            .doc = "Returns the map element that the iterator refers to.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, map::iterator::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class IncrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPostfix,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeMapIterator(type::Wildcard())},
            .result_doc = "iterator<map<*>>",
            .ns = "map::iterator",
            .doc = "Advances the iterator by one map element, returning the previous position.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, map::iterator::IncrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPostfix);

class IncrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPrefix,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeMapIterator(type::Wildcard())},
            .result_doc = "iterator<map<*>>",
            .ns = "map::iterator",
            .doc = "Advances the iterator by one map element, returning the new position.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, map::iterator::IncrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPrefix);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeMapIterator(type::Wildcard())},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMapIterator(type::Wildcard())},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "map::iterator",
            .doc = "Returns true if two map iterators refer to the same location.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, map::iterator::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeMapIterator(type::Wildcard())},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMapIterator(type::Wildcard())},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "map::iterator",
            .doc = "Returns true if two map iterators refer to different locations.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, map::iterator::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

} // namespace iterator

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Size,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .result = {.constness = Constness::Const, .type = builder->typeUnsignedInteger(64)},
            .ns = "map",
            .doc = "Returns the number of elements a map contains.",
        };
    }

    HILTI_OPERATOR(hilti, map::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "map",
            .doc = "Compares two maps element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, map::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "map",
            .doc = "Compares two maps element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, map::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class In : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::In,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeAny()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "map",
            .doc = "Returns true if an element is part of the map.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForType(builder, parameter::Kind::In,
                                   operands[1]->type()->type()->as<type::Map>()->keyType()->type());
        auto* op1 = operandForExpression(builder, parameter::Kind::In, operands, 1);
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, map::In)
};
HILTI_OPERATOR_IMPLEMENTATION(In);

class Delete : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Delete,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeMap(type::Wildcard())},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeAny()},
            .result = {.constness = Constness::Const, .type = builder->typeVoid()},
            .ns = "map",
            .doc = "Removes an element from the map.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto* op1 = operandForType(builder, parameter::Kind::In,
                                   operands[0]->type()->type()->as<type::Map>()->keyType()->type());
        return {{op0, op1}};
    }

    HILTI_OPERATOR(hilti, map::Delete)
};
HILTI_OPERATOR_IMPLEMENTATION(Delete)

class IndexConst : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Index,
            .priority = Priority::Low,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeAny()},
            .result_doc = "<type of element>",
            .ns = "map",
            .doc =
                "Returns the map's element for the given key. The key must exist, otherwise the operation "
                "will throw a runtime error.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        auto* op1 = operandForType(builder, parameter::Kind::In,
                                   operands[0]->type()->type()->as<type::Map>()->keyType()->type());
        return {{op0, op1}};
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Map>()->valueType()->recreateAsConst(builder->context());
    }


    HILTI_OPERATOR(hilti, map::IndexConst)
};
HILTI_OPERATOR_IMPLEMENTATION(IndexConst);

class IndexNonConst : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Index,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeMap(type::Wildcard())},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeAny()},
            .result_doc = "<type of element>",
            .ns = "map",
            .doc =
                "Returns the map's element for the given key. The key must exist, otherwise the operation "
                "will throw a runtime error.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto* op1 = operandForType(builder, parameter::Kind::In,
                                   operands[0]->type()->type()->as<type::Map>()->keyType()->type());
        return {{op0, op1}};
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Map>()->valueType()->recreateAsLhs(builder->context());
    }

    HILTI_OPERATOR(hilti, map::IndexNonConst)
};
HILTI_OPERATOR_IMPLEMENTATION(IndexNonConst);

class IndexAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IndexAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeMap(type::Wildcard())},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeAny()},
            .op2 = {.kind = parameter::Kind::In, .type = builder->typeAny()},
            .result = {.constness = Constness::Const, .type = builder->typeVoid()},
            .ns = "map",
            .doc = "Updates the map value for a given key. If the key does not exist a new element is inserted.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        auto* op1 = operandForType(builder, parameter::Kind::In,
                                   operands[0]->type()->type()->as<type::Map>()->keyType()->type());
        auto* op2 = operandForType(builder, parameter::Kind::In,
                                   operands[0]->type()->type()->as<type::Map>()->valueType()->type());
        return {{op0, op1, op2}};
    }

    HILTI_OPERATOR(hilti, map::IndexAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(IndexAssign);

class Get : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .member = "get",
            .param0 =
                {
                    .name = "key",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeAny()},
                },
            .param1 =
                {
                    .name = "default",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeAny()},
                    .optional = true,
                },
            .result_doc = "<type of element>",
            .ns = "map",
            .doc = R"(
Returns the map's element for the given key. If the key does not exist, returns
the default value if provided; otherwise throws a runtime error.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Map>()->valueType()->recreateAsLhs(builder->context());
    }

    HILTI_OPERATOR(hilti, map::Get);
};
HILTI_OPERATOR_IMPLEMENTATION(Get);

class GetOptional : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeMap(type::Wildcard())},
            .member = "get_optional",
            .param0 =
                {
                    .name = "key",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeAny()},
                },
            .result_doc = "optional<type of element>",
            .ns = "map",
            .doc = R"(
Returns an optional either containing the map's element for the given key if
that entry exists, or an unset optional if it does not.
)",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return builder->qualifiedType(builder->typeOptional(operands[0]->type()->type()->as<type::Map>()->valueType()),
                                      Constness::Const);
    }

    HILTI_OPERATOR(hilti, map::GetOptional);
};
HILTI_OPERATOR_IMPLEMENTATION(GetOptional);

class Clear : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::InOut, .type = builder->typeMap(type::Wildcard())},
            .member = "clear",
            .result = {.constness = Constness::Const, .type = builder->typeVoid()},
            .ns = "map",
            .doc = R"(
Removes all elements from the map.
)",
        };
    }

    HILTI_OPERATOR(hilti, map::Clear);
};
HILTI_OPERATOR_IMPLEMENTATION(Clear);

} // namespace map
} // namespace
