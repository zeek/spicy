// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <string>
#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/expressions/type.h>
#include <hilti/ast/operators/generic.h>
#include <hilti/ast/types/address.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/error.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/real.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/type.h>

using namespace hilti;
using namespace hilti::operator_;

namespace hilti::generic {

CastedCoercion::~CastedCoercion() {}
HILTI_OPERATOR_IMPLEMENTATION(CastedCoercion);

operator_::Signature CastedCoercion::signature(Builder* builder) const {
    return Signature{
        .kind = Kind::Cast,
        .op0 = {parameter::Kind::In, builder->typeAny(), "<dynamic - no doc>"},
        .op1 = {parameter::Kind::In, builder->typeAny(), "<dynamic - no doc>"},
        .op2 = {parameter::Kind::In, builder->typeAny(), "<dynamic - no doc>"},
        .result_doc = "<dynamic - no result>",
        .ns = "<dynamic - no ns>",
        .skip_doc = true,
    };
}

QualifiedType* CastedCoercion::result(Builder* builder, const Expressions& operands, const Meta& meta) const {
    return operands[1]->type()->type()->as<type::Type_>()->typeValue();
}

Result<expression::ResolvedOperator*> CastedCoercion::instantiate(Builder* builder, Expressions operands,
                                                                  Meta meta) const {
    auto* result_ = result(builder, operands, meta);
    return {operator_::generic::CastedCoercion::create(builder->context(), this, result_, operands, std::move(meta))};
}

} // namespace hilti::generic

namespace {
namespace generic {

class Pack : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Pack,
            .op0 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .result = {Constness::Mutable, builder->typeBytes()},
            .ns = "generic",
            .doc = "Packs a value into a binary representation. See :ref:`packing` for details.",
        };
    }

    void validate(expression::ResolvedOperator* n) const final {
        const auto args = n->op0()->type()->type()->as<type::Tuple>()->elements();
        if ( args.empty() ) {
            n->addError("not enough arguments for pack operator");
            return;
        }

        const auto& input_type = args[0]->type()->type();

        if ( input_type->isA<type::SignedInteger>() || input_type->isA<type::UnsignedInteger>() ) {
            if ( args.size() == 2 ) {
                auto arg1 = args[1]->type()->type()->cxxID();
                if ( arg1 && arg1 == ID("::hilti::rt::ByteOrder") )
                    return;
            }

            n->addError("invalid arguments for integer packing; want (<value>, <ByteOrder>)");
            return;
        }

        else if ( input_type->isA<type::Address>() ) {
            if ( args.size() == 2 ) {
                auto arg1 = args[1]->type()->type()->cxxID();
                if ( arg1 && arg1 == ID("::hilti::rt::ByteOrder") )
                    return;
            }

            n->addError("invalid arguments for address packing; want (<value>, <ByteOrder>)");
            return;
        }

        else if ( input_type->isA<type::Real>() ) {
            if ( args.size() == 3 ) {
                auto arg1 = args[1]->type()->type()->cxxID();
                auto arg2 = args[2]->type()->type()->cxxID();
                if ( arg1 && arg1 == ID("::hilti::rt::real::Type") && arg2 && arg2 == ID("::hilti::rt::ByteOrder") )
                    return;
            }

            n->addError("invalid arguments for real packing; want (<value>, <RealType>, <ByteOrder>)");
            return;
        }

        else
            n->addError("type not packable");
    }

    HILTI_OPERATOR(hilti, generic::Pack)
};
HILTI_OPERATOR_IMPLEMENTATION(Pack);

class Unpack : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unpack,
            .op0 = {parameter::Kind::In, builder->typeType(type::Wildcard())},
            .op1 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .op2 = {parameter::Kind::In, builder->typeBool()},
            .result_doc = "<unpacked value>",
            .ns = "generic",
            .doc = "Unpacks a value from a binary representation. See :ref:`packing` for details.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        const auto args = operands[1]->type()->type()->as<type::Tuple>()->elements();
        if ( args.empty() )
            return builder->qualifiedType(builder->typeError(), Constness::Const);

        auto* t = builder->typeTuple(QualifiedTypes{operands[0]->type()->type()->as<type::Type_>()->typeValue(),
                                                    args[0]->type()},
                                     operands[0]->meta());

        if ( operands[2]->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value() )
            return builder->qualifiedType(t, Constness::Const);
        else
            return builder->qualifiedType(builder->typeResult(builder->qualifiedType(t, Constness::Const)),
                                          Constness::Const);
    }

    void validate(expression::ResolvedOperator* n) const final {
        const auto& data_type = n->op0()->type()->type()->as<type::Type_>()->typeValue()->type();

        const auto args = n->op1()->type()->type()->as<type::Tuple>()->elements();
        if ( args.size() < 1 ) {
            n->addError("not enough arguments for unpack operator");
            return;
        }

        const auto& input_type = args[0]->type()->type();
        if ( ! (input_type->isA<type::Bytes>() || input_type->isA<type::stream::View>()) ) {
            n->addError("unpack() can be used only with bytes or a stream view as input");
            return;
        }

        if ( data_type->isA<type::SignedInteger>() || data_type->isA<type::UnsignedInteger>() ) {
            if ( args.size() == 2 ) {
                auto arg1 = args[1]->type()->type()->cxxID();
                if ( arg1 && arg1 == ID("::hilti::rt::ByteOrder") )
                    return;
            }

            n->addError("invalid arguments for integer unpacking; want (<data>, <ByteOrder>)");
            return;
        }

        else if ( data_type->isA<type::Address>() ) {
            if ( args.size() == 3 ) {
                auto arg1 = args[1]->type()->type()->cxxID();
                auto arg2 = args[2]->type()->type()->cxxID();
                if ( arg1 && arg1 == ID("::hilti::rt::AddressFamily") && arg2 && arg2 == ID("::hilti::rt::ByteOrder") )
                    return;
            }

            n->addError("invalid arguments for address unpacking; want (<data>, <AddressFamily>, <ByteOrder>)");
            return;
        }

        else if ( data_type->isA<type::Real>() ) {
            if ( args.size() == 3 ) {
                auto arg1 = args[1]->type()->type()->cxxID();
                auto arg2 = args[2]->type()->type()->cxxID();
                if ( arg1 && arg1 == ID("::hilti::rt::real::Type") && arg2 && arg2 == ID("::hilti::rt::ByteOrder") )
                    return;
            }

            n->addError("invalid arguments for real unpacking; want (<data>, <RealType>, <ByteOrder>)");
            return;
        }

        else if ( data_type->isA<type::Bitfield>() ) {
            if ( args.size() >= 2 && args.size() <= 3 ) {
                auto arg1 = args[1]->type()->type()->cxxID();
                const auto& arg2 =
                    (args.size() > 2 ? args[2]->type()->type()->cxxID() : ID("::hilti::rt::integer::BitOrder"));
                if ( arg1 && arg1 == ID("::hilti::rt::ByteOrder") && arg2 &&
                     arg2 == ID("::hilti::rt::integer::BitOrder") )
                    return;
            }

            n->addError("invalid arguments for bitfield unpacking; want (<data>, <ByteOrder>[, <BitOrder>])");
            return;
        }

        else
            n->addError("type not unpackable");
    }

    HILTI_OPERATOR(hilti, generic::Unpack)
};
HILTI_OPERATOR_IMPLEMENTATION(Unpack);

class Begin : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Begin,
            .op0 = {parameter::Kind::In, builder->typeAny(), "<container>"},
            .result_doc = "<iterator>",
            .ns = "generic",
            .doc = "Returns an iterator to the beginning of the container's content.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        if ( auto* iter = operands[0]->type()->type()->iteratorType() )
            return iter;
        else
            return builder->qualifiedType(builder->typeError(), Constness::Const);
    }

    void validate(expression::ResolvedOperator* n) const final {
        if ( ! n->op0()->type()->type()->iteratorType() )
            n->addError("not an iterable type");
    }

    HILTI_OPERATOR(hilti, generic::Begin)
};
HILTI_OPERATOR_IMPLEMENTATION(Begin);

class End : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::End,
            .op0 = {parameter::Kind::In, builder->typeAny(), "<container>"},
            .result_doc = "<iterator>",
            .ns = "generic",
            .doc = "Returns an iterator to the end of the container's content.",
        };
    }

    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        if ( auto* iter = operands[0]->type()->type()->iteratorType() )
            return iter;
        else
            return builder->qualifiedType(builder->typeError(), Constness::Const);
    }

    void validate(expression::ResolvedOperator* n) const final {
        if ( ! n->op0()->type()->type()->iteratorType() )
            n->addError("not an iterable type");
    }

    HILTI_OPERATOR(hilti, generic::End)
};
HILTI_OPERATOR_IMPLEMENTATION(End);

class New : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::New,
            .op0 = {parameter::Kind::In, builder->typeAny(), "T"},
            .op1 = {parameter::Kind::In, builder->typeTuple(type::Wildcard())},
            .result_doc = "T&",
            .ns = "generic",
            .doc = R"(
Returns a :ref:`reference <type_reference>` to an instance of a type
newly allocated on the heap. If ``T`` is a type, a default instance of
that type will be allocated. If the type expects any parameters, they
must be provided through a corresponding argument tuple: ``new
T(ARG_1, ... ,ARG_N)``. If ``T`` is a constant, an instance of its type
will be allocated and initialized with the value. Other types of
expressions are not allowed.
)",
        };
    }
    QualifiedType* result(Builder* builder, const Expressions& operands, const Meta& meta) const final {
        auto* t = operands[0]->type();

        if ( auto* tv = operands[0]->type()->type()->tryAs<type::Type_>() )
            t = tv->typeValue();

        t = t->recreateAsLhs(builder->context());

        return builder->qualifiedType(builder->typeStrongReference(t, t->meta()), Constness::Const, Side::RHS);
    }

    void validate(expression::ResolvedOperator* n) const final {
        auto* t = n->operands()[0]->type();

        if ( auto* tv = n->operands()[0]->type()->type()->tryAs<type::Type_>() )
            t = tv->typeValue();

        if ( ! t->type()->isAllocable() )
            n->addError("not an allocable type");
    }

    HILTI_OPERATOR(hilti, generic::New)
};
HILTI_OPERATOR_IMPLEMENTATION(New);

} // namespace generic
} // namespace
