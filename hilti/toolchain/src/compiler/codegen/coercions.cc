// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/expressions/all.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/interval.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/ast/types/set.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/time.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/vector.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : public hilti::visitor::PreOrder {
    Visitor(CodeGen* cg, const cxx::Expression& expr, QualifiedType* src, QualifiedType* dst)
        : cg(cg), expr(expr), src(src), dst(dst) {}

    CodeGen* cg;
    const cxx::Expression& expr;
    QualifiedType* src = nullptr;
    QualifiedType* dst = nullptr;

    std::optional<cxx::Expression> result;

    void operator()(type::Bytes* n) final {
        if ( dst->type()->isA<type::Stream>() )
            result = fmt("::hilti::rt::Stream(%s)", expr);

        else
            logger().internalError(fmt("codegen: unexpected type coercion from bytes to %s", dst->type()->typename_()));
    }

    void operator()(type::Enum* n) final {
        if ( dst->type()->isA<type::Bool>() )
            result = fmt("::hilti::rt::enum_::has_label(%s, %s)", expr, cg->typeInfo(src));

        else
            logger().internalError(fmt("codegen: unexpected type coercion from enum to %s", dst->type()->typename_()));
    }

    void operator()(type::Error* n) final {
        if ( dst->type()->isA<type::Result>() )
            result = fmt("%s(%s)", cg->compile(dst, codegen::TypeUsage::Storage), expr);

        else
            logger().internalError(fmt("codegen: unexpected type coercion from error to %s", dst->type()->typename_()));
    }

    void operator()(type::Interval* n) final {
        if ( dst->type()->isA<type::Bool>() ) {
            auto id = cg->compile(src, codegen::TypeUsage::Storage);
            result = fmt("(%s != ::hilti::rt::Interval())", expr);
        }

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from interval to %s", dst->type()->typename_()));
    }

    void operator()(type::List* n) final {
        if ( dst->type()->isA<type::Set>() )
            result = fmt("::hilti::rt::Set(%s)", expr);

        else if ( dst->type()->isA<type::Vector>() ) {
            assert(type::same(n->elementType(), dst->type()->as<type::Vector>()->elementType()));
            result = expr;
        }

        else
            logger().internalError(fmt("codegen: unexpected type coercion from lisst to %s", dst->type()->typename_()));
    }

    void operator()(type::Name* n) final {
        assert(n->resolvedType());
        dispatch(n->resolvedType());
    }

    void operator()(type::Optional* n) final {
        if ( dst->type()->isA<type::Optional>() ) {
            // Create tmp to avoid evaluation "expr" twice.
            auto tmp = cg->addTmp("opt", cg->compile(src, codegen::TypeUsage::Storage));
            result = {fmt("(%s = (%s), %s.hasValue() ? hilti::rt::optional::make(*%s) : hilti::rt::Null())", tmp, expr,
                          tmp, tmp),
                      Side::LHS};
        }

        else if ( dst->type()->isA<type::Bool>() )
            result = fmt("%s.hasValue()", expr);

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from optional to %s", dst->type()->typename_()));
    }

    void operator()(type::StrongReference* n) final {
        if ( dst->type()->isA<type::Bool>() )
            result = fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        else if ( dst->type()->isA<type::ValueReference>() )
            result = fmt("%s.derefAsValue()", expr);

        else if ( auto* x = dst->type()->tryAs<type::WeakReference>() )
            result = fmt("::hilti::rt::WeakReference<%s>(%s)",
                         cg->compile(x->dereferencedType(), codegen::TypeUsage::Ctor), expr);

        else if ( type::same(n->dereferencedType(), dst) )
            result = {fmt("(*%s)", expr), Side::LHS};

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from %s to %s", *n, dst->type()->typename_()));
    }

    void operator()(type::String* n) final {
        if ( dst->type()->isA<type::Error>() )
            result = fmt("%s(%s)", cg->compile(dst, codegen::TypeUsage::Storage), expr);
    }

    void operator()(type::Time* n) final {
        if ( dst->type()->isA<type::Bool>() ) {
            auto id = cg->compile(src, codegen::TypeUsage::Storage);
            result = fmt("(%s != ::hilti::rt::Time())", expr);
        }

        else
            logger().internalError(fmt("codegen: unexpected type coercion from time to %s", dst->type()->typename_()));
    }

    void operator()(type::Result* n) final {
        if ( dst->type()->isA<type::Bool>() )
            result = fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        else if ( dst->type()->isA<type::Optional>() ) {
            // Create tmp to avoid evaluation "expr" twice.
            auto tmp = cg->addTmp("result", cg->compile(src, codegen::TypeUsage::Storage));
            result = {fmt("(%s = (%s), %s.hasValue() ? hilti::rt::optional::make(*%s) : hilti::rt::Null())", tmp, expr,
                          tmp, tmp),
                      Side::LHS};
        }

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from result to %s", dst->type()->typename_()));
    }

    void operator()(type::SignedInteger* n) final {
        if ( dst->type()->isA<type::Bool>() )
            result = fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        else if ( auto* x = dst->type()->tryAs<type::SignedInteger>() )
            result = fmt("::hilti::rt::integer::safe<int%d_t>(%s)", x->width(), expr);

        else if ( auto* x = dst->type()->tryAs<type::UnsignedInteger>() )
            result = fmt("::hilti::rt::integer::safe<uint%d_t>(%s)", x->width(), expr);

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from signed integer to %s", dst->type()->typename_()));
    }

    void operator()(type::Stream* n) final {
        if ( dst->type()->isA<type::stream::View>() )
            result = fmt("%s.view()", expr);

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from stream to %s", dst->type()->typename_()));
    }

    void operator()(type::Union* n) final {
        if ( dst->type()->isA<type::Bool>() ) {
            auto id = cg->compile(src, codegen::TypeUsage::Storage);
            result = fmt("(%s.index() > 0)", expr);
        }

        else
            logger().internalError(fmt("codegen: unexpected type coercion from union to %s", dst->type()->typename_()));
    }

    void operator()(type::stream::View* n) final {
        if ( dst->type()->isA<type::Bytes>() )
            result = fmt("%s.data()", expr);

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from view<stream> to %s", dst->type()->typename_()));
    }

    void operator()(type::Type_* n) final {
        if ( auto* lt = dst->type()->tryAs<type::Library>(); lt && lt->cxxName() == "::hilti::rt::TypeInfo*" )
            result = cg->typeInfo(n->typeValue());
        else
            result = cg->coerce(expr, n->typeValue(), dst);
    }

    void operator()(type::Tuple* n) final {
        if ( auto* x = dst->type()->tryAs<type::Tuple>() ) {
            assert(n->elements().size() == x->elements().size());

            std::vector<cxx::Expression> exprs;

            // Check if a coercion is needed at all.
            bool all_same_types = true;
            for ( auto i = 0U; i < n->elements().size(); ++i ) {
                if ( ! type::same(n->elements()[i]->type(), x->elements()[i]->type()) ) {
                    all_same_types = false;
                    break;
                }
            }

            if ( all_same_types ) {
                result = fmt("%s", expr);
                return;
            }

            // Coerce individual fields. We do this in a lambda to avoid
            // emitting multiple full tupled constructors for temporaries.
            for ( auto i = 0U; i < n->elements().size(); i++ ) {
                exprs.push_back(cg->coerce(fmt("::hilti::rt::tuple::get<%d>(%s)", i, HILTI_INTERNAL_ID("t")),
                                           n->elements()[i]->type(), x->elements()[i]->type()));
            }

            result = fmt("[&](const auto& %s) { return hilti::rt::tuple::make(%s); }(%s)", HILTI_INTERNAL_ID("t"),
                         util::join(exprs, ", "), expr);
        }

        else
            logger().internalError(fmt("codegen: unexpected type coercion from tuple to %s", dst->type()->typename_()));
    }

    void operator()(type::UnsignedInteger* n) final {
        if ( dst->type()->isA<type::Bool>() )
            result = fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        else if ( auto* x = dst->type()->tryAs<type::SignedInteger>() )
            result = fmt("::hilti::rt::integer::safe<int%d_t>(%s)", x->width(), expr);

        else if ( auto* x = dst->type()->tryAs<type::UnsignedInteger>() )
            result = fmt("::hilti::rt::integer::safe<uint%d_t>(%s)", x->width(), expr);

        else if ( dst->type()->isA<type::Bitfield>() )
            result = cg->unsignedIntegerToBitfield(dst, expr, cxx::Expression("::hilti::rt::integer::BitOrder::LSB0"));
        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from unsigned integer to %s", dst->type()->typename_()));
    }

    void operator()(type::WeakReference* n) final {
        if ( dst->type()->isA<type::Bool>() )
            result = fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        else if ( auto* x = dst->type()->tryAs<type::StrongReference>() )
            result = fmt("::hilti::rt::StrongReference<%s>(%s.derefAsValue())",
                         cg->compile(x->dereferencedType(), codegen::TypeUsage::Ctor), expr);

        else if ( dst->type()->isA<type::ValueReference>() )
            result = fmt("%s.derefAsValue()", expr);

        else if ( type::same(n->dereferencedType(), dst) )
            result = {fmt("(*%s)", expr), Side::LHS};

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from weak reference to %s", dst->type()->typename_()));
    }

    void operator()(type::ValueReference* n) final {
        if ( auto* x = dst->type()->tryAs<type::Bool>() )
            result = cg->coerce(fmt("*%s", expr), x->dereferencedType(), dst);

        else if ( auto* x = dst->type()->tryAs<type::ValueReference>();
                  x && type::same(x->dereferencedType()->type(), x->dereferencedType()->type()) )
            result = fmt("%s", expr);

        else if ( auto* x = dst->type()->tryAs<type::StrongReference>() )
            result = fmt("::hilti::rt::StrongReference<%s>(%s)",
                         cg->compile(x->dereferencedType(), codegen::TypeUsage::Ctor), expr);

        else if ( auto* x = dst->type()->tryAs<type::WeakReference>() )
            result = fmt("::hilti::rt::WeakReference<%s>(%s)",
                         cg->compile(x->dereferencedType(), codegen::TypeUsage::Ctor), expr);

        else if ( type::same(n->dereferencedType(), dst) )
            result = {fmt("(*%s)", expr), Side::LHS};

        else
            logger().internalError(
                fmt("codegen: unexpected type coercion from value reference to %s", dst->type()->typename_()));
    }

    void operator()(type::Null* n) final {
        if ( dst->type()->tryAs<type::StrongReference>() || dst->type()->tryAs<type::WeakReference>() )
            result = expr;
        else if ( dst->type()->isA<type::Bool>() )
            result = "::hilti::rt::Bool(false)";
        else
            logger().internalError(fmt("codegen: unexpected type coercion from null to %s", dst->type()->typename_()));
    }
};

} // anonymous namespace

cxx::Expression CodeGen::coerce(const cxx::Expression& e, QualifiedType* src, QualifiedType* dst) {
    if ( type::sameExceptForConstness(src, dst) )
        // If only difference is constness, nothing to do.
        return e;

    if ( auto* t = dst->type()->tryAs<type::Optional>();
         t && ! src->type()->isA<type::Optional>() &&
         ! src->type()->isA<type::Result>() ) { // TODO: Should not need to white-list result here, but we need its
                                                // dedicated coercion code.
        // Special case `Null`. Since standard conversions run before the
        // user-defined conversion operation from `Null` to `std::optional` we
        // might end up using a standard conversion which might be invalid.
        auto maybe_expr = src->type()->isA<type::Null>() ? "" : e;
        return fmt("%s(%s)", compile(dst, codegen::TypeUsage::Storage), maybe_expr);
    }

    if ( dst->type()->isA<type::Result>() )
        return fmt("%s(%s)", compile(dst, codegen::TypeUsage::Storage), e);

    if ( dst->type()->tryAs<type::ValueReference>() && ! src->type()->isReferenceType() )
        return e;

    auto v = Visitor(this, e, src, dst);
    if ( auto nt = hilti::visitor::dispatch(v, src->type(), [](const auto& v) -> const auto& { return v.result; }) )
        return *nt;

    logger().internalError(fmt("codegen: type %s unhandled for coercion", src->type()->typename_()));
}
