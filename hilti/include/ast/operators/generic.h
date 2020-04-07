// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/expressions/type.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/type.h>

namespace hilti {
namespace operator_ {

BEGIN_OPERATOR_CUSTOM(generic, Unpack)
    Type result(const std::vector<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<unpackable>");

        auto data_type = ops[1].type().as<type::Tuple>().types()[0];
        return type::Result(type::Tuple({ops[0].type().as<type::Type_>().typeValue(), data_type}, ops[0].meta()));
    }

    bool isLhs() const { return false; }

    std::vector<Operand> operands() const {
        return {{.type = type::Type_(type::Wildcard())}, {.type = type::Tuple(type::Wildcard())}};
    }

    void validate(const expression::ResolvedOperator& i, operator_::const_position_t /*p */) const {
        auto data_type = i.op1().type().template as<type::Tuple>().types()[0];

        if ( ! (data_type.isA<type::Bytes>() || data_type.isA<type::stream::View>()) )
            logger().error("unpack() can be used only with bytes or a stream view as input", i);
    }

    std::string doc() const { return "Unpacks a value from a binary representation."; }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(generic, Begin)
    Type result(const std::vector<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<iterable>");

        return type::isIterable(ops[0].type()) ? ops[0].type().iteratorType(ops[0].isConstant()) : type::unknown;
    }

    bool isLhs() const { return false; }

    std::vector<Operand> operands() const {
        return {
            {.type = type::Any()},
        };
    }

    void validate(const expression::ResolvedOperator& i, operator_::const_position_t /* p */) const {
        if ( ! type::isIterable(i.operands()[0].type()) )
            logger().error("not an iterable type", i);
    }

    std::string doc() const { return "Returns an iterator to the beginning of a container's content."; }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(generic, End)
    Type result(const std::vector<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<iterable>");

        return type::isIterable(ops[0].type()) ? ops[0].type().iteratorType(ops[0].isConstant()) : type::unknown;
    }

    bool isLhs() const { return false; }

    std::vector<Operand> operands() const {
        return {
            {.type = type::Any()},
        };
    }

    void validate(const expression::ResolvedOperator& i, operator_::const_position_t /* p */) const {
        if ( ! type::isIterable(i.operands()[0].type()) )
            logger().error("not an iterable type", i);
    }

    std::string doc() const { return "Returns an iterator to the end of a container's content."; }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(generic, New)
    Type result(const std::vector<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("strong_ref<T>");

        auto t = ops[0].type();

        if ( auto tv = ops[0].type().tryAs<type::Type_>() )
            t = tv->typeValue();

        return type::StrongReference(t, t.meta());
    }

    bool isLhs() const { return false; }

    std::vector<Operand> operands() const {
        return {
            {.id = "t", .type = type::Any()},
            {.type = type::Tuple(type::Wildcard())},
        };
    }

    void validate(const expression::ResolvedOperator& i, operator_::const_position_t /* p */) const {
        auto t = i.operands()[0].type();

        if ( auto tv = i.operands()[0].type().tryAs<type::Type_>() )
            t = tv->typeValue();

        if ( ! type::isAllocable(t) )
            logger().error("not an allocable type", i);
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
        std::vector<operator_::Operand> operands() const { return {}; } // Won't participate in overload resolution
        Type result(const std::vector<Expression>& ops) const { return ops[1].as<expression::Type_>().typeValue(); }
        bool isLhs() const { return false; }
        void validate(const expression::ResolvedOperator& /* i */, operator_::const_position_t /* p */) const {}
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

} // namespace operator_
} // namespace hilti
