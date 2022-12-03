// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/operators/real.h>
#include <hilti/ast/operators/signed-integer.h>
#include <hilti/ast/types/integer.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;

namespace {

// For now, this is only a very basic constant folder that only covers cases we
// need to turn type constructor expressions coming with a single argument into
// ctor expressions.
struct VisitorConstantFolder : public visitor::PreOrder<Ctor, VisitorConstantFolder> {
    // Helper to cast an uint64 to int64, with range check.
    int64_t to_int64(uint64_t x, position_t& p) {
        if ( x > std::numeric_limits<int64_t>::max() )
            logger().error("signed integer value out of range 2", p.node.location());

        return static_cast<int64_t>(x);
    }

    result_t operator()(const expression::Ctor& n, position_t p) { return n.ctor(); }

    result_t operator()(const operator_::signed_integer::SignNeg& n, position_t p) {
        if ( auto op = detail::foldConstant<ctor::SignedInteger>(n.op1()) ) {
            if ( op->value() >= 0 ) {
                if ( op->value() < -std::numeric_limits<int64_t>::min() ) {
                    logger().error("signed integer value out of range X", p.node.location());
                    return {};
                }
            }
            else {
                if ( -op->value() > std::numeric_limits<int64_t>::max() ) {
                    logger().error("signed integer value out of range Y", p.node.location());
                    return {};
                }
            }

            return ctor::SignedInteger(-op->value(), op->width(), op->meta());
        }
        else
            return {};
    }

    result_t operator()(const operator_::real::SignNeg& n, position_t p) {
        if ( auto op = detail::foldConstant<ctor::Real>(n.op1()) )
            return ctor::Real(-op->value(), op->meta());
        else
            return {};
    }
};

} // anonymous namespace

Result<Ctor> detail::foldConstant(const Expression& expr) {
    auto v = VisitorConstantFolder();

    if ( auto ctor = v.dispatch(expr) )
        return *ctor;
    else
        return result::Error("not a foldable constant expression");
}
