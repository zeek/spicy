// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/tuple.h>

namespace hilti {
namespace operator_ {

STANDARD_OPERATOR_2(tuple, Equal, type::Bool(), type::constant(type::Tuple(type::Wildcard())),
                    operator_::sameTypeAs(0, "tuple<*>"), "Compares two tuples element-wise.");
STANDARD_OPERATOR_2(tuple, Unequal, type::Bool(), type::constant(type::Tuple(type::Wildcard())),
                    operator_::sameTypeAs(0, "tuple<*>"), "Compares two tuples element-wise.");

BEGIN_OPERATOR_CUSTOM(tuple, Index)
    Type result(const std::vector<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<type of element>");

        auto i = ops[1].as<expression::Ctor>().ctor().as<ctor::UnsignedInteger>();
        return ops[0].type().as<type::Tuple>().types()[i.value()];
    }

    bool isLhs() const { return false; }

    std::vector<Operand> operands() const {
        return {{.type = type::Tuple(type::Wildcard())}, {.type = type::UnsignedInteger(64)}};
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        if ( auto ec = i.op1().tryAs<expression::Ctor>() )
            if ( auto c = ec->ctor().tryAs<ctor::UnsignedInteger>() ) {
                if ( c->value() < 0 || c->value() >= i.op0().type().as<type::Tuple>().types().size() )
                    p.node.addError("tuple index out of range");

                return;
            }

        p.node.addError("tuple index must be an integer constant");
    }

    std::string doc() const {
        return "Extracts the tuple element at the given index. The index must be a constant unsigned integer.";
    }
END_OPERATOR_CUSTOM

BEGIN_OPERATOR_CUSTOM(tuple, Member)
    Type result(const std::vector<Expression>& ops) const {
        if ( ops.empty() )
            return type::DocOnly("<type of element>");

        auto id = ops[1].as<expression::Member>().id();
        auto elem = ops[0].type().as<type::Tuple>().elementByID(id);
        if ( ! elem )
            return type::unknown;

        return elem->second;
    }

    bool isLhs() const { return false; }

    std::vector<Operand> operands() const {
        return {{.type = type::Tuple(type::Wildcard())}, {.type = type::Member(type::Wildcard()), .doc = "<id>"}};
    }

    void validate(const expression::ResolvedOperator& i, operator_::position_t p) const {
        auto id = i.operands()[1].as<expression::Member>().id();
        auto elem = i.operands()[0].type().as<type::Tuple>().elementByID(id);

        if ( ! elem )
            p.node.addError("unknown tuple element");
    }

    std::string doc() const { return "Extracts the tuple element corresponding to the given ID."; }
END_OPERATOR_CUSTOM_x


} // namespace operator_
} // namespace hilti
