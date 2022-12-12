// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <optional>

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

#include "exception.h"

using namespace hilti;

namespace {

// Internal version of _foldConstant() that passes expceptions through to caller.
static Result<Ctor> _foldConstant(const Node& expr);

template<typename Ctor>
Result<Ctor> foldConstant(const Expression& expr) {
    auto ctor = _foldConstant(expr);
    if ( ! ctor )
        return ctor.error();

    if ( auto ctor_ = ctor->tryAs<Ctor>() )
        return *ctor_;
    else
        return result::Error("unexpected type");
}

// For now, this is only a very basic constant folder that only covers cases we
// need to turn type constructor expressions coming with a single argument into
// ctor expressions.
struct VisitorConstantFolder : public visitor::PreOrder<std::optional<Ctor>, VisitorConstantFolder> {
    // Helper to replace an type constructor expression that receives a
    // constant argument with a corresponding ctor expression.
    template<typename Ctor, typename Operator, typename Fn>
    result_t tryReplaceCtorExpression(const Operator& op, position_t p, Fn cb) {
        if ( auto ctor = foldConstant<Ctor>(callArgument(op, 0)) ) {
            auto x = cb(*ctor);
            x.setMeta(p.node.meta());
            return {std::move(x)};
        }
        else
            return std::nullopt;
    }

    // Helper to extract the 1st argument of a call expression.
    Expression callArgument(const expression::ResolvedOperatorBase& o, int i) {
        auto ctor = o.op1().as<expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor.as<ctor::Tuple>().value()[i];
    }

    // Helper to cast an uint64 to int64, with range check.
    int64_t to_int64(uint64_t x, position_t& p) {
        if ( x > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<int64_t>(x);
    }

    // Overload that doesn't need to do any checking.
    int64_t to_int64(int64_t x, position_t& p) { return x; }

    // Helper to cast an int64 to uint64, with range check.
    uint64_t to_uint64(int64_t x, position_t& p) {
        if ( x < 0 )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<uint64_t>(x);
    }

    result_t operator()(const expression::Ctor& n, position_t p) { return n.ctor(); }

    result_t operator()(const operator_::signed_integer::SignNeg& n, position_t p) {
        auto op = foldConstant<ctor::SignedInteger>(n.op0());
        if ( ! op )
            return std::nullopt;

        return ctor::SignedInteger(-op->value(), op->width(), p.node.meta());
    }

    result_t operator()(const operator_::unsigned_integer::SignNeg& n, position_t p) {
        auto op = foldConstant<ctor::UnsignedInteger>(n.op0());
        if ( ! op )
            return std::nullopt;

        if ( op->value() > std::abs(std::numeric_limits<int64_t>::min()) )
            throw hilti::rt::OutOfRange("integer value out of range");

        return ctor::SignedInteger(-static_cast<int64_t>(op->value()), op->width(), p.node.meta());
    }

    result_t operator()(const operator_::real::SignNeg& n, position_t p) {
        auto op = foldConstant<ctor::Real>(n.op0());
        if ( ! op )
            return std::nullopt;

        return ctor::Real(-op->value(), p.node.meta());
    }

    result_t operator()(const operator_::error::Ctor& op, position_t p) {
        return tryReplaceCtorExpression<ctor::Error>(op, p, [](const auto& ctor) { return ctor::Error(ctor.value()); });
    }

    result_t operator()(const operator_::interval::CtorSignedIntegerSecs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [](const auto& ctor) {
            return ctor::Interval(ctor::Interval::Value(ctor.value(), hilti::rt::Interval::SecondTag()));
        });
    }

    result_t operator()(const operator_::interval::CtorUnsignedIntegerSecs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [](const auto& ctor) {
            return ctor::Interval(ctor::Interval::Value(ctor.value(), hilti::rt::Interval::SecondTag()));
        });
    }

    result_t operator()(const operator_::interval::CtorSignedIntegerNs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [](const auto& ctor) {
            return ctor::Interval(ctor::Interval::Value(ctor.value(), hilti::rt::Interval::NanosecondTag()));
        });
    }

    result_t operator()(const operator_::interval::CtorUnsignedIntegerNs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [](const auto& ctor) {
            return ctor::Interval(ctor::Interval::Value(ctor.value(), hilti::rt::Interval::NanosecondTag()));
        });
    }

    result_t operator()(const operator_::interval::CtorRealSecs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::Real>(op, p, [](const auto& ctor) {
            return ctor::Interval(ctor::Interval::Value(ctor.value(), hilti::rt::Interval::SecondTag()));
        });
    }

    result_t operator()(const operator_::port::Ctor& op, position_t p) {
        return tryReplaceCtorExpression<ctor::Port>(op, p, [](const auto& ctor) {
            return ctor::Port(ctor::Port::Value(ctor.value()));
        });
    }

    result_t operator()(const operator_::signed_integer::CtorSigned8& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::SignedInteger(to_int64(ctor.value(), p), 8);
        });
    }

    result_t operator()(const operator_::signed_integer::CtorSigned16& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::SignedInteger(to_int64(ctor.value(), p), 16);
        });
    }

    result_t operator()(const operator_::signed_integer::CtorSigned32& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::SignedInteger(to_int64(ctor.value(), p), 32);
        });
    }

    result_t operator()(const operator_::signed_integer::CtorSigned64& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::SignedInteger(to_int64(ctor.value(), p), 64);
        });
    }

    result_t operator()(const operator_::signed_integer::CtorUnsigned8& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::SignedInteger(to_int64(ctor.value(), p), 8);
        });
    }

    result_t operator()(const operator_::signed_integer::CtorUnsigned16& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::SignedInteger(to_int64(ctor.value(), p), 16);
        });
    }

    result_t operator()(const operator_::signed_integer::CtorUnsigned32& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::SignedInteger(to_int64(ctor.value(), p), 32);
        });
    }

    result_t operator()(const operator_::signed_integer::CtorUnsigned64& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::SignedInteger(to_int64(ctor.value(), p), 64);
        });
    }

    result_t operator()(const operator_::time::CtorSignedIntegerSecs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [](const auto& ctor) {
            return ctor::Time(ctor::Time::Value(ctor.value(), hilti::rt::Time::SecondTag()));
        });
    }

    result_t operator()(const operator_::time::CtorUnsignedIntegerSecs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [](const auto& ctor) {
            return ctor::Time(ctor::Time::Value(ctor.value(), hilti::rt::Time::SecondTag()));
        });
    }

    result_t operator()(const operator_::stream::Ctor& op, position_t p) {
        return tryReplaceCtorExpression<ctor::Stream>(op, p,
                                                      [](const auto& ctor) { return ctor::Stream(ctor.value()); });
    }

    result_t operator()(const operator_::time::CtorSignedIntegerNs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [](const auto& ctor) {
            return ctor::Time(ctor::Time::Value(ctor.value(), hilti::rt::Time::NanosecondTag()));
        });
    }

    result_t operator()(const operator_::time::CtorUnsignedIntegerNs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [](const auto& ctor) {
            return ctor::Time(ctor::Time::Value(ctor.value(), hilti::rt::Time::NanosecondTag()));
        });
    }

    result_t operator()(const operator_::time::CtorRealSecs& op, position_t p) {
        return tryReplaceCtorExpression<ctor::Real>(op, p, [](const auto& ctor) {
            return ctor::Time(ctor::Time::Value(ctor.value(), hilti::rt::Time::SecondTag()));
        });
    }

    result_t operator()(const operator_::unsigned_integer::CtorSigned8& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::UnsignedInteger(to_uint64(ctor.value(), p), 8);
        });
    }

    result_t operator()(const operator_::unsigned_integer::CtorSigned16& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::UnsignedInteger(to_uint64(ctor.value(), p), 16);
        });
    }

    result_t operator()(const operator_::unsigned_integer::CtorSigned32& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::UnsignedInteger(to_uint64(ctor.value(), p), 32);
        });
    }

    result_t operator()(const operator_::unsigned_integer::CtorSigned64& op, position_t p) {
        return tryReplaceCtorExpression<ctor::SignedInteger>(op, p, [this, &p](const auto& ctor) {
            return ctor::UnsignedInteger(to_uint64(ctor.value(), p), 64);
        });
    }

    result_t operator()(const operator_::unsigned_integer::CtorUnsigned8& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [](const auto& ctor) {
            return ctor::UnsignedInteger(ctor.value(), 8);
        });
    }

    result_t operator()(const operator_::unsigned_integer::CtorUnsigned16& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [](const auto& ctor) {
            return ctor::UnsignedInteger(ctor.value(), 16);
        });
    }

    result_t operator()(const operator_::unsigned_integer::CtorUnsigned32& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [](const auto& ctor) {
            return ctor::UnsignedInteger(ctor.value(), 32);
        });
    }

    result_t operator()(const operator_::unsigned_integer::CtorUnsigned64& op, position_t p) {
        return tryReplaceCtorExpression<ctor::UnsignedInteger>(op, p, [](const auto& ctor) {
            return ctor::UnsignedInteger(ctor.value(), 64);
        });
    }
};

Result<Ctor> _foldConstant(const Node& expr) {
    auto v = VisitorConstantFolder();

    if ( auto ctor = v.dispatch(expr); ctor && *ctor )
        return **ctor;
    else
        return result::Error("not a foldable constant expression");
}

} // anonymous namespace

Result<std::optional<Ctor>> detail::foldConstant(const Node& expr) {
    try {
        auto v = VisitorConstantFolder();

        if ( auto ctor = v.dispatch(expr) )
            return *ctor;
        else
            return {std::nullopt};
    } catch ( const hilti::rt::RuntimeError& e ) {
        return result::Error(e.what());
    }
}
