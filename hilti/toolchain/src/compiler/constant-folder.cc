// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/safe-math.h>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/grouping.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/operators/all.h>
#include <hilti/ast/types/integer.h>
#include <hilti/base/logger.h>
#include <hilti/base/result.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/constant-folder.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>

using namespace hilti;
using namespace hilti::detail::constant_folder;

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Resolver("resolver");
} // namespace hilti::logging::debug

namespace {

// Internal version of _foldConstant() that passes exceptions through to caller.
static Result<Ctor*> foldConstant(Builder* builder, Expression* expr, bitmask<Style> style);

template<typename Ctor>
Result<Ctor*> foldConstant(Builder* builder, Expression* expr, bitmask<Style> style) {
    auto ctor = foldConstant(builder, expr, style);
    if ( ! ctor )
        return ctor.error();

    assert(*ctor);
    if ( auto ctor_ = (*ctor)->tryAs<Ctor>() )
        return ctor_;
    else
        return result::Error("unexpected type");
}

// For now, this is only a very basic constant folder that only covers cases we
// need to turn type constructor expressions coming with a single argument into
// ctor expressions.
struct VisitorConstantFolder : public visitor::PreOrder {
    VisitorConstantFolder(Builder* builder, bitmask<Style> style) : builder(builder), style(style) {}

    Builder* builder;
    bitmask<Style> style;

    Ctor* result = nullptr;

    // Helper to replace an type constructor expression that receives a
    // constant argument with a corresponding ctor expression.
    template<typename Ctor, typename OperatorPtr, typename Fn>
    hilti::Ctor* tryReplaceCtorExpression(const OperatorPtr& op, Fn cb) {
        if ( auto ctor = foldConstant<Ctor>(builder, callArgument(op, 0), style) ) {
            auto x = cb(*ctor);
            x->setMeta(op->meta());
            return x;
        }
        else
            return nullptr;
    }

    // Helper to extract the 1st argument of a call expression.
    Expression* callArgument(const expression::ResolvedOperator* o, int i) {
        auto* ctor = o->op1()->as<expression::Ctor>()->ctor();

        if ( auto* x = ctor->tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor->as<ctor::Tuple>()->value()[i];
    }

    // Helper to cast an uint64 to int64, with range check.
    int64_t to_int64(uint64_t x) {
        try {
            return SafeInt<int64_t>(x);
        } catch ( ... ) {
            throw hilti::rt::OutOfRange("integer value out of range");
        }
    }

    // Helper to cast an int64 to uint64, with range check.
    uint64_t to_uint64(int64_t x) {
        if ( x < 0 )
            throw hilti::rt::OutOfRange("integer value out of range");

        return static_cast<uint64_t>(x);
    }

    void operator()(expression::Ctor* n) final {
        if ( auto* coerced = n->ctor()->tryAs<ctor::Coerced>() )
            result = coerced->coercedCtor();
        else
            result = n->ctor();
    }

    void operator()(operator_::signed_integer::SignNeg* n) final {
        if ( auto op = foldConstant<ctor::SignedInteger>(builder, n->op0(), style) )
            result = builder->ctorSignedInteger(-(*op)->value(), (*op)->width(), n->meta());
    }

    void operator()(expression::Grouping* n) final {
        if ( n->local() )
            // Don't fold if there is a local variable.
            return;

        if ( auto x = foldConstant(builder, n->expression(), style) )
            result = *x;
    }

    void operator()(expression::LogicalOr* n) final {
        auto op0 = foldConstant<ctor::Bool>(builder, n->op0(), style);
        auto op1 = foldConstant<ctor::Bool>(builder, n->op1(), style);
        if ( op0 && op1 )
            result = builder->ctorBool((*op0)->value() || (*op1)->value(), n->meta());
    }

    void operator()(expression::LogicalAnd* n) final {
        auto op0 = foldConstant<ctor::Bool>(builder, n->op0(), style);
        auto op1 = foldConstant<ctor::Bool>(builder, n->op1(), style);
        if ( op0 && op1 )
            result = builder->ctorBool((*op0)->value() && (*op1)->value(), n->meta());
    }

    void operator()(expression::LogicalNot* n) final {
        if ( auto op = foldConstant<ctor::Bool>(builder, n->expression(), style) )
            result = builder->ctorBool(! (*op)->value(), n->meta());
    }

    void operator()(expression::Name* n) final {
        if ( ! n->resolvedDeclarationIndex() )
            return;

        if ( hilti::detail::Optimizer::isFeatureFlag(n->id()) && ! (style & Style::InlineFeatureConstants) )
            return;

        auto* decl = n->resolvedDeclaration();
        auto* const_ = decl->tryAs<declaration::Constant>();
        if ( ! const_ )
            return;

        auto x = foldConstant(builder, const_->value(), style);
        if ( ! x )
            return;

        result = *x;
    }

    void operator()(expression::Ternary* n) final {
        if ( ! (style & Style::FoldTernaryOperator) )
            return;

        if ( auto bool_ = foldConstant<ctor::Bool>(builder, n->condition(), style) ) {
            auto* true_ = n->true_()->tryAs<expression::Ctor>();
            auto* false_ = n->false_()->tryAs<expression::Ctor>();
            if ( true_ && false_ )
                result = ((*bool_)->value() ? true_->ctor() : false_->ctor());
        }
    }

    void operator()(operator_::unsigned_integer::SignNeg* n) final {
        auto op = foldConstant<ctor::UnsignedInteger>(builder, n->op0(), style);
        if ( op )
            result =
                builder->ctorSignedInteger(hilti::rt::integer::safe_negate((*op)->value()), (*op)->width(), n->meta());
    }

    void operator()(operator_::real::SignNeg* n) final {
        if ( auto op = foldConstant<ctor::Real>(builder, n->op0(), style) )
            result = builder->ctorReal(-(*op)->value(), n->meta());
    }

    void operator()(operator_::error::Ctor* n) final {
        result =
            tryReplaceCtorExpression<ctor::Error>(n, [this](auto* ctor) { return builder->ctorError(ctor->value()); });
    }

    void operator()(operator_::interval::CtorSignedIntegerSecs* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](auto* ctor) {
            return builder->ctorInterval(hilti::rt::Interval(ctor->value(), hilti::rt::Interval::SecondTag()));
        });
    }

    void operator()(operator_::interval::CtorUnsignedIntegerSecs* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](auto* ctor) {
            return builder->ctorInterval(hilti::rt::Interval(ctor->value(), hilti::rt::Interval::SecondTag()));
        });
    }

    void operator()(operator_::interval::CtorSignedIntegerNs* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](auto* ctor) {
            return builder->ctorInterval(hilti::rt::Interval(ctor->value(), hilti::rt::Interval::NanosecondTag()));
        });
    }

    void operator()(operator_::interval::CtorUnsignedIntegerNs* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](auto* ctor) {
            return builder->ctorInterval(hilti::rt::Interval(ctor->value(), hilti::rt::Interval::NanosecondTag()));
        });
    }

    void operator()(operator_::interval::CtorRealSecs* n) final {
        result = tryReplaceCtorExpression<ctor::Real>(n, [this](auto* ctor) {
            return builder->ctorInterval(hilti::rt::Interval(ctor->value(), hilti::rt::Interval::SecondTag()));
        });
    }

    void operator()(operator_::port::Ctor* n) final {
        result =
            tryReplaceCtorExpression<ctor::Port>(n, [this](auto* ctor) { return builder->ctorPort(ctor->value()); });
    }

    void operator()(operator_::signed_integer::CtorSigned8* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](const auto& ctor) {
            return builder->ctorSignedInteger(ctor->value(), 8);
        });
    }

    void operator()(operator_::signed_integer::CtorSigned16* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](const auto& ctor) {
            return builder->ctorSignedInteger(ctor->value(), 16);
        });
    }

    void operator()(operator_::signed_integer::CtorSigned32* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](const auto& ctor) {
            return builder->ctorSignedInteger(ctor->value(), 32);
        });
    }

    void operator()(operator_::signed_integer::CtorSigned64* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](const auto& ctor) {
            return builder->ctorSignedInteger(ctor->value(), 64);
        });
    }

    void operator()(operator_::signed_integer::CtorUnsigned8* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](const auto& ctor) {
            return builder->ctorSignedInteger(to_int64(ctor->value()), 8);
        });
    }

    void operator()(operator_::signed_integer::CtorUnsigned16* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](const auto& ctor) {
            return builder->ctorSignedInteger(to_int64(ctor->value()), 16);
        });
    }

    void operator()(operator_::signed_integer::CtorUnsigned32* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](const auto& ctor) {
            return builder->ctorSignedInteger(to_int64(ctor->value()), 32);
        });
    }

    void operator()(operator_::signed_integer::CtorUnsigned64* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](const auto& ctor) {
            return builder->ctorSignedInteger(to_int64(ctor->value()), 64);
        });
    }

    void operator()(operator_::time::CtorSignedIntegerSecs* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](auto* ctor) {
            return builder->ctorTime(hilti::rt::Time(ctor->value(), hilti::rt::Time::SecondTag()));
        });
    }


    void operator()(operator_::time::CtorUnsignedIntegerSecs* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](auto* ctor) {
            return builder->ctorTime(hilti::rt::Time(ctor->value(), hilti::rt::Time::SecondTag()));
        });
    }

    void operator()(operator_::stream::Ctor* n) final {
        result = tryReplaceCtorExpression<ctor::Stream>(n, [this](auto* ctor) {
            return builder->ctorStream(ctor->value());
        });
    }

    void operator()(operator_::time::CtorSignedIntegerNs* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](auto* ctor) {
            return builder->ctorTime(hilti::rt::Time(ctor->value(), hilti::rt::Time::NanosecondTag()));
        });
    }

    void operator()(operator_::time::CtorUnsignedIntegerNs* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](auto* ctor) {
            return builder->ctorTime(hilti::rt::Time(ctor->value(), hilti::rt::Time::NanosecondTag()));
        });
    }

    void operator()(operator_::time::CtorRealSecs* n) final {
        result = tryReplaceCtorExpression<ctor::Real>(n, [this](auto* ctor) {
            return builder->ctorTime(hilti::rt::Time(ctor->value(), hilti::rt::Time::SecondTag()));
        });
    }

    void operator()(operator_::unsigned_integer::CtorSigned8* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](auto* ctor) {
            return builder->ctorUnsignedInteger(to_uint64(ctor->value()), 8);
        });
    }

    void operator()(operator_::unsigned_integer::CtorSigned16* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](auto* ctor) {
            return builder->ctorUnsignedInteger(to_uint64(ctor->value()), 16);
        });
    }

    void operator()(operator_::unsigned_integer::CtorSigned32* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](auto* ctor) {
            return builder->ctorUnsignedInteger(to_uint64(ctor->value()), 32);
        });
    }

    void operator()(operator_::unsigned_integer::CtorSigned64* n) final {
        result = tryReplaceCtorExpression<ctor::SignedInteger>(n, [this](auto* ctor) {
            return builder->ctorUnsignedInteger(to_uint64(ctor->value()), 64);
        });
    }

    void operator()(operator_::unsigned_integer::CtorUnsigned8* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](auto* ctor) {
            return builder->ctorUnsignedInteger(ctor->value(), 8);
        });
    }

    void operator()(operator_::unsigned_integer::CtorUnsigned16* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](auto* ctor) {
            return builder->ctorUnsignedInteger(ctor->value(), 16);
        });
    }

    void operator()(operator_::unsigned_integer::CtorUnsigned32* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](auto* ctor) {
            return builder->ctorUnsignedInteger(ctor->value(), 32);
        });
    }

    void operator()(operator_::unsigned_integer::CtorUnsigned64* n) final {
        result = tryReplaceCtorExpression<ctor::UnsignedInteger>(n, [this](auto* ctor) {
            return builder->ctorUnsignedInteger(ctor->value(), 64);
        });
    }
};

Result<Ctor*> foldConstant(Builder* builder, Expression* expr, bitmask<Style> style) {
    if ( auto* result = hilti::visitor::dispatch(VisitorConstantFolder(builder, style), expr,
                                                 [](const auto& v) { return v.result; }) )
        return result;
    else
        return result::Error("not a foldable constant expression");
}

} // anonymous namespace

Result<Ctor*> detail::constant_folder::foldExpression(Builder* builder, Expression* expr, bitmask<Style> style) {
    // By default, we don't fold away direct, top-level references to constant IDs. It's
    // likely as least as efficient to leave them as is, and potentially more.
    // For boolean, this can still be enabled through a style flag, which the
    // optimizer uses.
    if ( const auto* n = expr->tryAs<expression::Name>();
         n && (! (style & Style::InlineBooleanConstants) || ! n->type()->type()->isA<type::Bool>()) )
        return {nullptr};

    try {
        if ( auto* result = hilti::visitor::dispatch(VisitorConstantFolder(builder, style), expr,
                                                     [](const auto& v) { return v.result; }) )
            return result;
        else
            return {nullptr};
    } catch ( const hilti::rt::RuntimeError& e ) {
        return result::Error(e.what());
    }
}

struct VisitorConstantFolderAST : visitor::MutatingPostOrder {
    explicit VisitorConstantFolderAST(Builder* builder, Node* root, bitmask<Style> style)
        : visitor::MutatingPostOrder(builder, logging::debug::Resolver), style(style) {}

    bitmask<Style> style;

    void operator()(Expression* n) final {
        if ( n->isResolved() && ! n->isA<expression::Ctor>() ) {
            auto ctor = detail::constant_folder::foldExpression(builder(), n, style);
            if ( ! ctor ) {
                n->addError(ctor.error());
                return;
            }

            if ( *ctor ) {
                auto* nexpr = builder()->expressionCtor(*ctor, (*ctor)->meta());
                replaceNode(n, nexpr);
            }
        }
    }
};

bool detail::constant_folder::fold(Builder* builder, Node* node, bitmask<Style> style) {
    bool modified = false;

    while ( true ) {
        auto v = VisitorConstantFolderAST(builder, node, style);
        hilti::visitor::visit(v, node);

        if ( v.isModified() )
            modified = true;
        else
            return modified;
    }
}
