// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/expressions/type.h>
#include <hilti/ast/operators/common.h>
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

namespace hilti::operator_ {

BEGIN_OPERATOR_CUSTOM(generic, Pack)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<packable>");

        return type::Bytes();
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {Operand{{}, type::Tuple(type::Wildcard())}};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        const auto args = i.op0().type().template as<type::Tuple>().elements();

        if ( args.empty() ) {
            p.node.addError("not enough arguments for pack operator");
            return;
        }

        const auto& input_type = args[0].type();

        if ( input_type.isA<type::SignedInteger>() || input_type.isA<type::UnsignedInteger>() ) {
            if ( args.size() == 2 ) {
                auto arg1 = args[1].type().typeID();
                if ( arg1 && arg1->local() == ID("ByteOrder") )
                    return;
            }

            p.node.addError("invalid arguments for integer packing; want (<value>, <ByteOrder>)");
            return;
        }

        else if ( input_type.isA<type::Address>() ) {
            if ( args.size() == 2 ) {
                auto arg1 = args[1].type().typeID();
                if ( arg1 && arg1->local() == ID("ByteOrder") )
                    return;
            }

            p.node.addError("invalid arguments for address packing; want (<value>, <ByteOrder>)");
            return;
        }

        else if ( input_type.isA<type::Real>() ) {
            if ( args.size() == 3 ) {
                auto arg1 = args[1].type().typeID();
                auto arg2 = args[2].type().typeID();
                if ( arg1 && arg1->local() == ID("RealType") && arg2 && arg2->local() == ID("ByteOrder") )
                    return;
            }

            p.node.addError("invalid arguments for real packing; want (<value>, <RealType>, <ByteOrder>)");
            return;
        }

        else
            p.node.addError("type not packable");
    }

    std::string doc() const { return "Packs a value into a binary representation."; }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(generic, Unpack)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<unpackable>");

        const auto args = ops[1].type().template as<type::Tuple>().elements();
        if ( args.empty() )
            return type::Error();

        auto t = type::Tuple({ops[0].type().as<type::Type_>().typeValue(), args[0].type()}, ops[0].meta());

        auto throw_on_error = ops[2].as<expression::Ctor>().ctor().as<ctor::Bool>().value();
        return throw_on_error ? Type(t) : Type(type::Result(t));
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {Operand{{}, type::Type_(type::Wildcard())},
                                                 Operand{{}, type::Tuple(type::Wildcard())}, Operand({}, type::Bool())};
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        const auto& data_type = i.op0().type().as<type::Type_>().typeValue();
        const auto args = i.op1().type().template as<type::Tuple>().elements();

        if ( args.size() < 1 ) {
            p.node.addError("not enough arguments for unpack operator");
            return;
        }

        const auto& input_type = args[0].type();

        if ( ! (input_type.isA<type::Bytes>() || input_type.isA<type::stream::View>()) ) {
            p.node.addError("unpack() can be used only with bytes or a stream view as input");
            return;
        }

        if ( data_type.isA<type::SignedInteger>() || data_type.isA<type::UnsignedInteger>() ) {
            if ( args.size() == 2 ) {
                auto arg1 = args[1].type().typeID();
                if ( arg1 && arg1->local() == ID("ByteOrder") )
                    return;
            }

            p.node.addError("invalid arguments for integer unpacking; want (<data>, <ByteOrder>)");
            return;
        }

        else if ( data_type.isA<type::Address>() ) {
            if ( args.size() == 3 ) {
                auto arg1 = args[1].type().typeID();
                auto arg2 = args[2].type().typeID();
                if ( arg1 && arg1->local() == ID("AddressFamily") && arg2 && arg2->local() == ID("ByteOrder") )
                    return;
            }

            p.node.addError("invalid arguments for address unpacking; want (<data>, <AddressFamily>, <ByteOrder>)");
            return;
        }

        else if ( data_type.isA<type::Real>() ) {
            if ( args.size() == 3 ) {
                auto arg1 = args[1].type().typeID();
                auto arg2 = args[2].type().typeID();
                if ( arg1 && arg1->local() == ID("RealType") && arg2 && arg2->local() == ID("ByteOrder") )
                    return;
            }

            p.node.addError("invalid arguments for real unpacking; want (<data>, <RealType>, <ByteOrder>)");
            return;
        }

        else
            p.node.addError("type not unpackable");
    }

    std::string doc() const { return "Unpacks a value from a binary representation."; }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(generic, Begin)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<iterator>");

        return type::isIterable(ops[0].type()) ? ops[0].type().iteratorType(ops[0].isConstant()) : type::unknown;
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {
            Operand{{}, type::Any(), false, {}, "<container>"},
        };
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        const auto& typ = i.operands()[0].type();
        if ( ! type::isIterable(typ) )
            p.node.addError(util::fmt("'%s' not an iterable type", typ));
    }

    std::string doc() const { return "Returns an iterator to the beginning of the container's content."; }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(generic, End)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<iterator>");

        return type::isIterable(ops[0].type()) ? ops[0].type().iteratorType(ops[0].isConstant()) : type::unknown;
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {
            {{}, type::Any(), false, {}, "<container>"},
        };
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        const auto& typ = i.operands()[0].type();
        if ( ! type::isIterable(typ) )
            p.node.addError(util::fmt("'%s' not an iterable type", typ));
    }

    std::string doc() const { return "Returns an iterator to the end of the container's content."; }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(generic, New)
    Type result(const hilti::node::Range<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("strong_ref<T>");

        auto t = ops[0].type();

        if ( auto tv = ops[0].type().tryAs<type::Type_>() )
            t = tv->typeValue();

        return type::StrongReference(t, t.meta());
    }

    bool isLhs() const { return false; }
    auto priority() const { return hilti::operator_::Priority::Normal; }

    const std::vector<Operand>& operands() const {
        static std::vector<Operand> _operands = {
            {"t", type::Any()},
            {{}, type::Tuple(type::Wildcard())},
        };
        return _operands;
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        auto t = i.operands()[0].type();

        if ( auto tv = i.operands()[0].type().tryAs<type::Type_>() )
            t = tv->typeValue();

        if ( ! type::isAllocable(t) )
            p.node.addError("not an allocable type");
    }

    std::string doc() const {
        return R"(
Returns a reference to an instance of a type newly allocated on the heap.
If `x' is a type, a default instance of that type will be allocated.
If `x` is an expression, an instance of the expression's type will be allocated and initialized with the value of the expression.
)";
    }
END_OPERATOR_CUSTOM

/**
 * Operator created internally by the resolver for a cast expression
 * requesting a type coercion. This is mainly just a wrapper around a
 * CoercedExpression so that we don't loose the information that it was cast.
 */
OPERATOR_DECLARE_ONLY(generic, CastedCoercion)

namespace generic {

class CastedCoercion : public hilti::expression::ResolvedOperatorBase {
public:
    using hilti::expression::ResolvedOperatorBase::ResolvedOperatorBase;

    struct Operator : public hilti::trait::isOperator {
        Operator() = default;

        static operator_::Kind kind() { return operator_::Kind::Cast; }
        const std::vector<operator_::Operand>& operands() const {
            static std::vector<Operand> _operands = {}; // Won't participate in overload resolution
            return _operands;
        }
        Type result(const hilti::node::Range<Expression>& ops) const {
            return ops[1].as<expression::Type_>().typeValue();
        }
        bool isLhs() const { return false; }
        auto priority() const { return hilti::operator_::Priority::Normal; }
        void validate(const expression::ResolvedOperator& /* i */, operator_::position_t /* p */) const {}
        std::string doc() const { return "<dynamic - no doc>"; }
        std::string docNamespace() const { return "<dynamic - no ns>"; }

        Expression instantiate(const std::vector<Expression>& operands, const Meta& meta) const {
            auto ro = expression::ResolvedOperator(CastedCoercion(*this, operands, meta));
            ro.setMeta(meta);
            return std::move(ro);
        }
    };
};
} // namespace generic

} // namespace hilti::operator_
