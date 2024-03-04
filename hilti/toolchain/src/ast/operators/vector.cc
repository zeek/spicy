// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/vector.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace vector {
namespace iterator {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {parameter::Kind::In, builder->typeVectorIterator(type::Wildcard())},
            .result_doc = "<dereferenced type>",
            .ns = "vector::iterator",
            .doc = "Returns the vector element that the iterator refers to.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->dereferencedType();
    }

    HILTI_OPERATOR(hilti, vector::iterator::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class IncrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPostfix,
            .op0 = {parameter::Kind::InOut, builder->typeVectorIterator(type::Wildcard())},
            .result_doc = "iterator<vector<*>>",
            .ns = "vector::iterator",
            .doc = "Advances the iterator by one vector element, returning the previous position.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, vector::iterator::IncrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPostfix);

class IncrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPrefix,
            .op0 = {parameter::Kind::InOut, builder->typeVectorIterator(type::Wildcard())},
            .result_doc = "iterator<vector<*>>",
            .ns = "vector::iterator",
            .doc = "Advances the iterator by one vector element, returning the new position.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, vector::iterator::IncrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPrefix);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeVectorIterator(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeVectorIterator(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "vector::iterator",
            .doc = "Returns true if two vector iterators refer to the same location.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, vector::iterator::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);


class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeVectorIterator(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeVectorIterator(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "vector::iterator",
            .doc = "Returns true if two vector iterators refer to different locations.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, vector::iterator::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

} // namespace iterator

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Size,
            .op0 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .result = {Constness::Const, builder->typeUnsignedInteger(64)},
            .ns = "vector",
            .doc = "Returns the number of elements a vector contains.",
        };
    }

    HILTI_OPERATOR(hilti, vector::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "vector",
            .doc = "Compares two vectors element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, vector::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "vector",
            .doc = "Compares two vectors element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, vector::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class IndexConst : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Index,
            .priority = Priority::Low,
            .op0 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
            .result_doc = "<type of element>",
            .ns = "vector",
            .doc = "Returns the vector element at the given index.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Vector>()->elementType();
    }

    HILTI_OPERATOR(hilti, vector::IndexConst)
};

HILTI_OPERATOR_IMPLEMENTATION(IndexConst);
class IndexNonConst : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Index,
            .op0 = {parameter::Kind::InOut, builder->typeVector(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
            .result_doc = "<type of element>",
            .ns = "vector",
            .doc = "Returns the vector element at the given index.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Vector>()->elementType()->recreateAsLhs(builder->context());
    }

    HILTI_OPERATOR(hilti, vector::IndexNonConst)
};
HILTI_OPERATOR_IMPLEMENTATION(IndexNonConst);

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Sum,
            .op0 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .result_doc = "vector<*>",
            .ns = "vector",
            .doc = "Returns the concatenation of two vectors.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, vector::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum)

class SumAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SumAssign,
            .op0 = {parameter::Kind::InOut, builder->typeVector(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .result_doc = "vector<*>",
            .ns = "vector",
            .doc = "Concatenates another vector to the vector.",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto op0 = operandForExpression(builder, parameter::Kind::InOut, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, vector::SumAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssign)


class Assign : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .member = "assign",
            .param0 =
                {
                    .name = "i",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .param1 =
                {
                    .name = "x",
                    .type = {parameter::Kind::In, builder->typeAny()},
                },
            .result = {Constness::Const, builder->typeVoid()},
            .ns = "vector",
            .doc = R"(
Assigns *x* to the *i*th element of the vector. If the vector contains less
than *i* elements a sufficient number of default-initialized elements is added
to carry out the assignment.
)",
        };
    }

    HILTI_OPERATOR(hilti, vector::Assign);
};
HILTI_OPERATOR_IMPLEMENTATION(Assign);

class PushBack : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::InOut, builder->typeVector(type::Wildcard())},
            .member = "push_back",
            .param0 =
                {
                    .name = "x",
                    .type = {parameter::Kind::In, builder->typeAny()},
                },
            .result = {Constness::Const, builder->typeVoid()},
            .ns = "vector",
            .doc = R"(
Appends *x* to the end of the vector.
)",
        };
    }

    HILTI_OPERATOR(hilti, vector::PushBack);
};
HILTI_OPERATOR_IMPLEMENTATION(PushBack);

class PopBack : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::InOut, builder->typeVector(type::Wildcard())},
            .member = "pop_back",
            .result = {Constness::Const, builder->typeVoid()},
            .ns = "vector",
            .doc = R"(
Removes the last element from the vector, which must be non-empty.
)",
        };
    }

    HILTI_OPERATOR(hilti, vector::PopBack);
};
HILTI_OPERATOR_IMPLEMENTATION(PopBack);

class Front : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .member = "front",
            .result_doc = "<type of element>",
            .ns = "vector",
            .doc = R"(
Returns the first element of the vector. It throws an exception if the vector is
empty.
)",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Vector>()->elementType();
    }

    HILTI_OPERATOR(hilti, vector::Front);
};
HILTI_OPERATOR_IMPLEMENTATION(Front);

class Back : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .member = "back",
            .result_doc = "<type of element>",
            .ns = "vector",
            .doc = R"(
Returns the last element of the vector. It throws an exception if the vector is
empty.
)",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Vector>()->elementType();
    }

    HILTI_OPERATOR(hilti, vector::Back);
};
HILTI_OPERATOR_IMPLEMENTATION(Back);

class Reserve : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .member = "reserve",
            .param0 =
                {
                    .name = "n",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .result = {Constness::Const, builder->typeVoid()},
            .ns = "vector",
            .doc = R"(
Reserves space for at least *n* elements. This operation does not change the
vector in any observable way but provides a hint about the size that will be
needed.
)",
        };
    }

    HILTI_OPERATOR(hilti, vector::Reserve);
};
HILTI_OPERATOR_IMPLEMENTATION(Reserve);

class Resize : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .member = "resize",
            .param0 =
                {
                    .name = "n",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .result = {Constness::Const, builder->typeVoid()},
            .ns = "vector",
            .doc = R"(
Resizes the vector to hold exactly *n* elements. If *n* is larger than the
current size, the new slots are filled with default values. If *n* is smaller
than the current size, the excessive elements are removed.
)",
        };
    }

    HILTI_OPERATOR(hilti, vector::Resize);
};
HILTI_OPERATOR_IMPLEMENTATION(Resize);

class At : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .member = "at",
            .param0 =
                {
                    .name = "i",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .result_doc = "<iterator>",
            .ns = "vector",
            .doc = R"(
Returns an iterator referring to the element at vector index *i*.
)",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type()->type()->as<type::Vector>()->iteratorType();
    }

    HILTI_OPERATOR(hilti, vector::At);
};
HILTI_OPERATOR_IMPLEMENTATION(At);

class SubRange : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .member = "sub",
            .param0 =
                {
                    .name = "begin",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .param1 =
                {
                    .name = "end",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .result_doc = "vector<*>",
            .ns = "vector",
            .doc = R"(
Extracts a subsequence of vector elements spanning from index *begin*
to (but not including) index *end*.
)",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, vector::SubRange);
};
HILTI_OPERATOR_IMPLEMENTATION(SubRange);

class SubEnd : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeVector(type::Wildcard())},
            .member = "sub",
            .param0 =
                {
                    .name = "end",
                    .type = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
                },
            .result_doc = "vector<*>",
            .ns = "vector",
            .doc = R"(
Extracts a subsequence of vector elements spanning from index *begin*
to (but not including) index *end*.
)",
        };
    }

    QualifiedTypePtr result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    HILTI_OPERATOR(hilti, vector::SubEnd);
};
HILTI_OPERATOR_IMPLEMENTATION(SubEnd);

} // namespace vector
} // namespace
