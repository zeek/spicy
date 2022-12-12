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
struct VisitorConstantFolder : public visitor::PreOrder<std::optional<Ctor>, VisitorConstantFolder> {
    result_t operator()(const expression::Ctor& n, position_t p) { return n.ctor(); }

    result_t operator()(const operator_::signed_integer::SignNeg& n, position_t p) {
        const auto& op0 = p.node.children()[1].as<Expression>(); // TODO
        auto op = detail::foldConstant<ctor::SignedInteger>(op0);
        if ( ! op )
            return std::nullopt;

        return ctor::SignedInteger(-op->value(), op->width(), p.node.meta());
    }

    result_t operator()(const operator_::unsigned_integer::SignNeg& n, position_t p) {
        const auto& op0 = p.node.children()[1].as<Expression>(); // TODO
        auto op = detail::foldConstant<ctor::UnsignedInteger>(op0);
        if ( ! op )
            return std::nullopt;

        if ( op->value() > std::abs(std::numeric_limits<int64_t>::min()) )
            throw hilti::rt::OutOfRange("integer value out of range A3");

        return ctor::SignedInteger(-static_cast<int64_t>(op->value()), op->width(), p.node.meta());
    }

    result_t operator()(const operator_::real::SignNeg& n, position_t p) {
        const auto& op0 = p.node.children()[1].as<Expression>(); // TODO
        auto op = detail::foldConstant<ctor::Real>(op0);
        if ( ! op )
            return std::nullopt;

        return ctor::Real(-op->value(), p.node.meta());
    }
};

} // anonymous namespace

Result<Ctor> detail::foldConstant(const Node& expr) {
    auto v = VisitorConstantFolder();

    if ( auto ctor = v.dispatch(expr); ctor && ctor->has_value() )
        return **ctor;
    else
        return result::Error("not a foldable constant expression");
}
