// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/operand-list.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/compiler/coercion.h>
#include <hilti/compiler/plugin.h>
#include <hilti/global.h>

using namespace hilti;
using namespace util;

namespace hilti::logging::debug {
inline const DebugStream Resolver("resolver");
} // namespace hilti::logging::debug

// Public version going through all plugins.
Result<Ctor> hilti::coerceCtor(Ctor c, const Type& dst, bitmask<CoercionStyle> style) {
    if ( c.type() == dst )
        return std::move(c);

    for ( auto p : plugin::registry().plugins() ) {
        if ( ! (p.coerce_ctor) )
            continue;

        if ( auto nc = (*p.coerce_ctor)(c, dst, style) )
            return *nc;
    }

    return result::Error("could not coeerce type for constructor");
}

static Result<Type> _coerceParameterizedType(const Type& src_, const Type& dst_, bitmask<CoercionStyle> style) {
    auto src = type::effectiveType(src_);
    Type dst = type::effectiveType(dst_);

    if ( src == dst )
        return dst;

    if ( src.typename_() != dst.typename_() )
        return {};

    if ( dst.isWildcard() )
        return src;

    auto params1 = src.typeParameters();
    auto params2 = dst.typeParameters();

    if ( params1.size() != params2.size() )
        return {};

    bool have_wildcard = false;
    for ( auto&& [p1, p2] : util::zip2(params1, params2) ) {
        auto t1 = p1.tryAs<Type>();
        auto t2 = p2.tryAs<Type>();

        if ( ! (t1 && t2) )
            // Don't have a generic node comparison for the individual
            // parameters, so just stop here and decline. (Note that the case
            // of src == dst has been handled already, that usually does it.)
            return {};

        t1 = type::effectiveType(*t1);
        t2 = type::effectiveType(*t2);

        if ( t2->isWildcard() )
            have_wildcard = true;

        if ( const auto& orig = t1->originalNode(); (style & CoercionStyle::PreferOriginalType) && orig )
            t1 = orig->as<Type>();

        if ( const auto& orig = t2->originalNode(); (style & CoercionStyle::PreferOriginalType) && orig )
            t2 = orig->as<Type>();

        if ( ! coerceType(*t1, *t2, style) )
            return {};
    }

    // If one of the parameter types is a wildcard, we return the original type
    // instead of the coerced destination type. That's a heuristic that isn't
    // perfect, but will generally do the job. What we'd actually need is a
    // generic way to retype the type parameters, so that we could coerce them
    // individually. But we don't have that capability because all the types
    // compute them dynamically.
    return have_wildcard ? src : dst;
}

static Result<Type> _coerceType(const Type& src_, const Type& dst_, bitmask<CoercionStyle> style) {
    auto src = type::effectiveType(src_);
    Type dst = type::effectiveType(dst_);

    // TODO(robin): Not sure if this should/must replicate all the type coercion
    // login in coerceExpression(). If so, we should factor that out.
    // Update: I believe the answer is yes ... Added a few more cases, but this will
    // likely need more work.

    if ( src == dst )
        return src;

    if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
        if ( auto opt = dst.tryAs<type::Optional>() ) {
            if ( dst.isWildcard() )
                return dst;

            // All types converts into a corresponding optional.
            if ( auto x = coerceType(src_, opt->dereferencedType(), style) )
                return {type::Optional(*x, src.meta())};
        }

        if ( auto opt = dst.tryAs<type::Result>() ) {
            if ( dst.isWildcard() )
                return dst;

            // All types converts into a corresponding result.
            if ( auto x = coerceType(src_, opt->dereferencedType(), style) )
                return {type::Result(*x, src.meta())};
        }

        if ( auto x = dst.tryAs<type::ValueReference>(); x && ! type::isReferenceType(src) ) {
            // All types converts into a corresponding value_ref.
            if ( auto y = coerceType(src_, x->dereferencedType(), style) )
                return {type::ValueReference(*x, src.meta())};
        }
    }

    if ( type::isParameterized(src) && type::isParameterized(dst) ) {
        if ( auto x = _coerceParameterizedType(src, dst, style) )
            return *x;
    }

    for ( auto p : plugin::registry().plugins() ) {
        if ( ! (p.coerce_type) )
            continue;

        if ( auto nt = (*p.coerce_type)(type::nonConstant(src), type::nonConstant(dst), style) )
            return type::nonConstant(*nt);
    }

    return result::Error("cannot coerce types");
}

// Public version going through all plugins.
Result<Type> hilti::coerceType(const Type& src_, const Type& dst_, bitmask<CoercionStyle> style) {
    auto src = type::effectiveType(src_);

    if ( const auto& orig = src.originalNode(); (style & CoercionStyle::PreferOriginalType) && orig ) {
        if ( auto nt = hilti::coerceType(type::effectiveType(orig->as<Type>()), dst_, style) )
            return *nt;
    }

    return _coerceType(src_, dst_, style);
}

std::string hilti::to_string(bitmask<CoercionStyle> style) {
    std::vector<std::string> labels;

    if ( style & CoercionStyle::PreferOriginalType )
        labels.emplace_back("prefer-original-type");

    if ( style & CoercionStyle::TryExactMatch )
        labels.emplace_back("try-exact-match");

    if ( style & CoercionStyle::TryConstPromotion )
        labels.emplace_back("try-const-promotion");

    if ( style & CoercionStyle::TryCoercion )
        labels.emplace_back("try-coercion");

    if ( style & CoercionStyle::Assignment )
        labels.emplace_back("assignment");

    if ( style & CoercionStyle::FunctionCall )
        labels.emplace_back("function-call");

    if ( style & CoercionStyle::OperandMatching )
        labels.emplace_back("operand-matching");

    if ( style & CoercionStyle::DisallowTypeChanges )
        labels.emplace_back("disallow-type-changes");

    if ( style & CoercionStyle::ContextualConversion )
        labels.emplace_back("contextual-conversion");

    return util::join(labels, ",");
};

Result<std::pair<bool, std::vector<Expression>>> hilti::coerceOperands(const std::vector<Expression>& exprs,
                                                                       const std::vector<operator_::Operand>& operands,
                                                                       bitmask<CoercionStyle> style) {
    int num_type_changes = 0;
    bool changed = false;
    std::vector<Expression> transformed;

    if ( exprs.size() > operands.size() )
        return result::Error("more expressions than operands");

    for ( const auto& [i, op] : util::enumerate(operands) ) {
        if ( i >= exprs.size() ) {
            // Running out of operands, must have a default or be optional.
            if ( op.default_ ) {
                transformed.push_back(*op.default_);
                changed = true;
            }
            else if ( op.optional ) {
                // transformed.push_back(hilti::expression::Ctor(hilti::ctor::Null()));
            }
            else
                return result::Error("stray operand");

            continue;
        }

        auto oat = operator_::type(op.type, exprs, transformed);

        if ( ! oat )
            return result::Error("could not look up operand type");

        auto result = coerceExpression(exprs[i], *oat, style);

        if ( result.coerced ) {
            HILTI_DEBUG(logging::debug::Resolver,
                        util::fmt("  [param %d] matching %s against %s -> success: %s (coerced expression is %s) (%s)",
                                  i, exprs[i].type(), *oat, result.coerced->type(),
                                  (result.coerced->isConstant() ? "const" : "non-const"),
                                  (result.consider_type_changed ? "type changed" : "type not changed")));
        }
        else {
            HILTI_DEBUG(logging::debug::Resolver,
                        util::fmt("  [param %d] matching %s against %s -> failure", i, exprs[i].type(), *oat));
            return result::Error("could not match coercion operands");
        }

        // We check if the primary type of the alternative has changed. Only
        // one operand must change its primary type for an alternative to
        // match.
        if ( result.consider_type_changed && (++num_type_changes > 1 || style & CoercionStyle::DisallowTypeChanges) &&
             ! (style & CoercionStyle::FunctionCall) )
            return result::Error("no valid coercion found");

        transformed.push_back(*result.coerced);

        if ( result.nexpr )
            changed = true;
    }

    return std::make_pair(changed, std::move(transformed));
}

static CoercedExpression _coerceExpression(const Expression& e, const Type& src_, const Type& dst_,
                                           bitmask<CoercionStyle> style) {
    std::unique_ptr<logging::DebugPushIndent> dbg_indent;

    if ( style & CoercionStyle::_Recursing )
        dbg_indent = std::make_unique<logging::DebugPushIndent>(logging::debug::Resolver);
    else
        style |= CoercionStyle::_Recursing;

    const auto no_change = CoercedExpression(e);
    auto src = type::effectiveType(src_);
    auto dst = type::effectiveType(dst_);
    CoercedExpression _result;
    int _line = 0;

#define RETURN(x)                                                                                                      \
    {                                                                                                                  \
        _result = (x);                                                                                                 \
        _line = __LINE__;                                                                                              \
        goto exit;                                                                                                     \
    }

    if ( style & CoercionStyle::TryExactMatch ) {
        if ( src == dst ) {
            if ( e.isConstant() == type::isConstant(dst) )
                RETURN(no_change);

            if ( style & CoercionStyle::OperandMatching && ! type::isMutable(dst) )
                RETURN(no_change);
        }

        if ( e.isConstant() == type::isConstant(dst) && type::isParameterized(src) && type::isParameterized(dst) &&
             _coerceParameterizedType(src, dst, CoercionStyle::TryExactMatch) )
            RETURN(no_change); // can say no_change because we're in the ExactMatch case
    }

    if ( style & CoercionStyle::TryConstPromotion ) {
        if ( style & (CoercionStyle::OperandMatching | CoercionStyle::FunctionCall) ) {
            // Don't allow a constant value to match a non-constant operand.
            if ( e.isConstant() && (! type::isConstant(dst)) && type::isMutable(dst) )
                RETURN(result::Error());

            if ( dst.isWildcard() && src.typename_() == dst.typename_() )
                RETURN(no_change);

            if ( src == dst )
                RETURN(no_change);

            if ( type::sameExceptForConstness(src, dst) ) {
                RETURN(no_change);
            }
        }

        if ( style & CoercionStyle::Assignment ) {
            if ( src == dst )
                RETURN(no_change);

            if ( type::sameExceptForConstness(src, dst) )
                RETURN(no_change);

            if ( dst.isWildcard() && src.typename_() == dst.typename_() )
                RETURN(no_change);
        }
    }

    else {
        if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
            // Don't allow assigning to a constant.
            if ( type::isConstant(dst) )
                RETURN(result::Error());
        }

        if ( style & CoercionStyle::OperandMatching ) {
            // Don't allow a constant value to match a non-constant operand.
            if ( e.isConstant() && ! (type::isConstant(dst) || ! type::isMutable(dst)) )
                RETURN(result::Error());
        }
    }

    if ( dst.isA<type::Any>() )
        // type::Any accepts anything without actual coercion.
        RETURN(no_change);

    if ( auto x = e.tryAs<expression::Member>() ) {
        // Make sure the expression remains a member expression, as we will
        // be expecting to cast it to that.
        if ( auto t = hilti::coerceType(x->type(), dst, style) ) {
            RETURN(CoercedExpression(src_, expression::Member(x->id(), *t, x->meta())));
        }
        else
            RETURN(result::Error());
    }

    if ( auto o = dst.template tryAs<type::OperandList>() ) {
        // Match tuple against operands according to function call rules.
        HILTI_DEBUG(logging::debug::Resolver, util::fmt("matching against call parameters"));
        logging::DebugPushIndent _(logging::debug::Resolver);

        auto c = e.template tryAs<expression::Ctor>();
        if ( ! c )
            RETURN(CoercedExpression());

        // TOOD(robin): Why do we need this block? We do a separate operand
        // matching afterwards, too.

        if ( auto t = c->ctor().template tryAs<hilti::ctor::Tuple>() ) {
            CoercionStyle function_style =
                (style & CoercionStyle::TryCoercion ? CoercionStyle::TryAllForFunctionCall :
                                                      CoercionStyle::TryDirectMatchForFunctionCall);
            if ( auto result = coerceOperands(t->value(), o->operands(), function_style) ) {
                if ( result->first ) {
                    RETURN(
                        CoercedExpression(e.type(), expression::Ctor(hilti::ctor::Tuple(std::move(result->second)))));
                }
                else {
                    RETURN(no_change);
                }
            }
        }

        RETURN(CoercedExpression());
    }

    if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
        if ( auto opt = dst.tryAs<type::Optional>() ) {
            if ( opt->isWildcard() )
                RETURN(no_change);

            // All types converts into a corresponding optional.
            if ( auto x = coerceExpression(e, opt->dereferencedType(), style) )
                RETURN(CoercedExpression(src_, expression::Coerced(*x.coerced, dst, e.meta())));
        }

        if ( auto result = dst.tryAs<type::Result>() ) {
            if ( result->isWildcard() )
                RETURN(no_change);

            // All types convert into a corresponding result.
            if ( auto x = coerceExpression(e, result->dereferencedType(), style) )
                RETURN(CoercedExpression(src_, expression::Coerced(*x.coerced, dst, e.meta())));
        }

        if ( auto x = dst.tryAs<type::ValueReference>(); x && ! type::isReferenceType(src) ) {
            // All types converts into a corresponding value_ref.
            if ( auto y = coerceExpression(e, x->dereferencedType(), style) )
                RETURN(CoercedExpression(src_, expression::Coerced(*y.coerced, dst, e.meta())));
        }
    }

    if ( style & CoercionStyle::TryCoercion ) {
        if ( auto c = e.tryAs<expression::Ctor>() ) {
            if ( auto nc = hilti::coerceCtor(c->ctor(), dst, style) )
                RETURN(CoercedExpression(src_, expression::Ctor(ctor::Coerced(c->ctor(), *nc, c->meta()), e.meta())));
        }

        if ( auto t = hilti::coerceType(src, dst, style) )
            // We wrap the expression into a coercion even if the new type is
            // the same as *dst*. That way the overloader has a way to
            // recognize that the types aren't identical.
            RETURN(CoercedExpression(src_, expression::Coerced(e, *t, e.meta())));
    }

    _result = result::Error();

exit:
    HILTI_DEBUG(logging::debug::Resolver,
                util::fmt("coercing %s %s (%s) to %s%s (%s) -> %s [%s] (%s) (#%d)",
                          (e.isConstant() ? "const" : "non-const"), to_node(src),
                          util::replace(src.typename_(), "hilti::type::", ""),
                          (type::isConstant(dst) ? "" : "non-const "), to_node(dst),
                          util::replace(dst.typename_(), "hilti::type::", ""),
                          (_result ?
                               util::fmt("%s %s (%s)", (_result.coerced->isConstant() ? "const" : "non-const"),
                                         _result.coerced->type(),
                                         util::replace(_result.coerced->type().typename_(), "hilti::type::", "")) :
                               "fail"),
                          to_string(style), e.meta().location(), _line));

    return _result;
}

CoercedExpression hilti::coerceExpression(const Expression& e, const Type& src_, const Type& dst_,
                                          bitmask<CoercionStyle> style) {
    auto src = type::effectiveType(src_);

    if ( const auto& orig = src.originalNode(); (style & CoercionStyle::PreferOriginalType) && orig ) {
        if ( auto nt = hilti::coerceExpression(e, type::effectiveType(orig->as<Type>()), dst_, style) )
            return nt;
    }

    return _coerceExpression(e, src_, dst_, style);
}

CoercedExpression hilti::coerceExpression(const Expression& e, const Type& dst, bitmask<CoercionStyle> style) {
    return coerceExpression(e, e.type(), dst, style);
}
