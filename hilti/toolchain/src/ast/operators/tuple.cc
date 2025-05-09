// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <string>
#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/types/tuple.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace tuple {

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "tuple",
            .doc = "Compares two tuples element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, tuple::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .result = {Constness::Const, builder->typeBool()},
            .ns = "tuple",
            .doc = "Compares two tuples element-wise.",
        };
    }

    std::optional<operator_::Operands> filter(Builder* builder, const Expressions& operands) const final {
        auto* op0 = operandForExpression(builder, parameter::Kind::In, operands, 0);
        return {{op0, op0}};
    }

    HILTI_OPERATOR(hilti, tuple::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class Index : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Index,
            .op0 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeUnsignedInteger(64)},
            .result_doc = "<type of element>",
            .ns = "tuple",
            .doc = "Extracts the tuple element at the given index. The index must be a constant unsigned integer.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        auto* ctor = operands[1]->tryAs<expression::Ctor>();
        if ( ! ctor )
            return builder->qualifiedType(builder->typeUnknown(), Constness::Const);

        auto* i = ctor->ctor()->tryAs<ctor::UnsignedInteger>();
        if ( ! i )
            return builder->qualifiedType(builder->typeUnknown(), Constness::Const);

        const auto& elements = operands[0]->type()->type()->as<type::Tuple>()->elements();

        if ( static_cast<uint64_t>(elements.size()) <= i->value() )
            return builder->qualifiedType(builder->typeUnknown(), Constness::Const);

        return elements[i->value()]->type()->recreateAsLhs(builder->context());
    }

    void validate(expression::ResolvedOperator* n) const final {
        if ( auto* ec = n->op1()->tryAs<expression::Ctor>() )
            if ( auto* c = ec->ctor()->tryAs<ctor::UnsignedInteger>() ) {
                if ( c->value() >=
                     static_cast<uint64_t>(n->op0()->type()->type()->as<type::Tuple>()->elements().size()) )
                    n->addError("tuple index out of range");

                return;
            }

        n->addError("tuple index must be an integer constant");
    }

    HILTI_OPERATOR(hilti, tuple::Index)
};
HILTI_OPERATOR_IMPLEMENTATION(Index);

class Member : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Member,
            .op0 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeMember(type::Wildcard()), "<id>"},
            .result_doc = "<type of element>",
            .ns = "tuple",
            .doc = "Extracts the tuple element corresponding to the given ID.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        const auto& id = operands[1]->as<expression::Member>()->id();
        auto* tt = operands[0]->type()->type()->tryAs<type::Tuple>();
        if ( ! tt )
            return builder->qualifiedType(builder->typeUnknown(), Constness::Const);

        auto elem = tt->elementByID(id);
        if ( ! elem )
            return builder->qualifiedType(builder->typeUnknown(), Constness::Const);

        return elem->second->type()->recreateAsLhs(builder->context());
    }

    void validate(expression::ResolvedOperator* n) const final {
        const auto& id = n->op1()->as<expression::Member>()->id();
        auto* tt = n->op0()->type()->type()->tryAs<type::Tuple>();
        if ( ! tt ) {
            n->addError("unknown tuple element");
            return;
        }

        auto elem = tt->elementByID(id);

        if ( ! elem )
            n->addError("unknown tuple element");
    }

    HILTI_OPERATOR(hilti, tuple::Member)
};
HILTI_OPERATOR_IMPLEMENTATION(Member);

class CustomAssign : public Operator {
public:
    // The operator gets instantiated only through the normalizer, but the
    // signature is used for documentation.
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::CustomAssign,
            .op0 = {parameter::Kind::InOut, builder->typeMember(type::Wildcard()), "(x,...,y)"},
            .op1 = {parameter::Kind::InOut, builder->typeTuple(type::Wildcard())},
            .result_doc = "<tuple>",
            .ns = "tuple",
            .doc = "Assigns element-wise to the left-hand-side tuple.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        return operands[0]->type();
    }

    void validate(expression::ResolvedOperator* n) const final {
        auto* lhs = n->operands()[0]->as<expression::Ctor>()->ctor()->as<ctor::Tuple>();
        auto* lhs_type = lhs->type()->type()->as<type::Tuple>();
        auto* rhs_type = n->operands()[1]->type()->type()->tryAs<type::Tuple>();
        if ( ! rhs_type ) {
            n->addError("rhs is not a tuple");
            return;
        }

        if ( lhs_type->elements().size() != rhs_type->elements().size() ) {
            n->addError("cannot assign tuples of different length");
            return;
        }

        const auto& lhs_value = lhs->value();
        const auto& lhs_type_elements = lhs_type->elements();
        const auto& rhs_type_elements = rhs_type->elements();

        for ( auto j = 0U; j < lhs_type->elements().size(); j++ ) {
            const auto& lhs_elem = lhs_value[j];
            const auto& lhs_elem_type = lhs_type_elements[j]->type();
            const auto& rhs_elem_type = rhs_type_elements[j]->type();

            if ( lhs_elem->type()->side() != Side::LHS )
                n->addError(util::fmt("cannot assign to expression: %s", *lhs_elem));

            if ( ! type::sameExceptForConstness(lhs_elem_type, rhs_elem_type) )
                n->addError(util::fmt("type mismatch for element %d in assignment, expected type %s but got %s", j,
                                      *lhs_elem_type, *rhs_elem_type));
        }
    }

    HILTI_OPERATOR(hilti, tuple::CustomAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(CustomAssign);

} // namespace tuple
} // namespace
