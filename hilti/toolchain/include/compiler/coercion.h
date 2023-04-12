// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/3rdparty/ArticleEnumClass-v2/EnumClass.h>

#include <hilti/ast/ctor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/type.h>
#include <hilti/base/util.h>

namespace hilti {

/** Tunes the specifics of a type coercion operation. */
enum class CoercionStyle {
    /**
     * Specifies that coercion is taking place in the context of a assignment
     * of the source expression to a variable of the destination type.
     */
    Assignment = (1U << 0U),

    /**
     * Specifies that coercion is taking place in the context of matching the
     * source expression against a target operand during operator resolution.
     */
    OperandMatching = (1U << 1U),

    /**
     * Specifies that coercion is taking place in the context of passing the
     * source expression to a function parameter of the target type.
     */
    FunctionCall = (1U << 2U),

    /**
     * Let coercion succeed if the types fully match. (You probably always
     * want this).
     */
    TryExactMatch = (1U << 3U),

    /**
     * Let coercion succeed if the source type can be converted into the
     * destination type by a legal constness change.
     */
    TryConstPromotion = (1U << 4U),

    /**
     * Let coercion succeed if the source type can be converted into the
     * destination type by any of the plugins' provided type coercions. (This
     * is the main path to performing actual coercions that change types.)
     */
    TryCoercion = (1U << 5U),

    /** Never allow any substantial type changes. */
    DisallowTypeChanges = (1U << 7U),

    /**
     * Signal that the coercion takes place in a semantic language context
     * expecting the given destination type. This can be used to support
     * coercions at locations where normally it wouldn't take place, such as
     * conversion to bool in conditional statements.
     */
    ContextualConversion = (1U << 8U),

    /** Internal flag signaling the coercion code is recursing. */
    _Recursing = (1U << 10U),

    /**
     * Shortcut style activating all possible coercions in the context of an
     * assignment.
     */
    TryAllForAssignment = (1U << 0U) | (1U << 3U) | (1U << 4U) | (1U << 5U) | (1U << 6U),

    /**
     * Shortcut style activating all possible coercions in the context of
     * operator resolution.
     */
    TryAllForMatching = (1U << 1U) | (1U << 3U) | (1U << 4U) | (1U << 5U) | (1U << 6U),

    /**
     * Shortcut style activating possible coercions in the context of
     * function parameter passing, however without allowing any type changes.
     */
    TryDirectMatchForFunctionCall = (1U << 2U) | (1U << 3U) | (1U << 4U) | (1U << 6U),

    /**
     * Shortcut style activating all possible coercions in the context of
     * function parameter passing.
     */
    TryAllForFunctionCall = (1U << 2U) | (1U << 3U) | (1U << 4U) | (1U << 5U) | (1U << 6U),

    /**
     * Shortcut style allowing for direct matches only in the context of
     * operator resolution.
     */
    TryDirectForMatching = (1U << 1U) | (1U << 3U) | (1U << 4U) | (1U << 6U)
};

/**
 * Returns a readable representation of a coercion style setting for debugging
 * purposes.
 */
extern std::string to_string(bitmask<CoercionStyle> style);

} // namespace hilti

enableEnumClassBitmask(hilti::CoercionStyle); // Must be in global scope

namespace hilti {

/** Return type for the functions doing expression coercion. */
struct CoercedExpression {
    /** Returns true if coercion was successful. */
    operator bool() const { return coerced.hasValue(); }

    /**
     * Coerced expression if successful, an error if not. This will be set
     * even if the coerced expression ends up being identical to the source
     * expression.
     */
    Result<Expression> coerced = {};

    /**
     * Coerced expression if successful and the coerced expression is not
     * identical to original one; unset otherwise.
     */
    std::optional<Expression> nexpr = {};

    /**
     * If coerced is set, true if type of new expression's type is to be
     * considered changed compared to source expression's type for overload
     * resolution
     */
    bool consider_type_changed = false;

    /**
     *
     * Represents a successful coercion that led the source expression not
     * changing, which will be assigned to the `coerced` field.
     *
     * @note The expression not changing doesn't necessarily mean that
     * the expression's type is *exactly* matching the coercion's destination
     * type. However, even if not, the caller should proceed by using the
     * `coerced` field value for anywhere where the coerced expression is
     * expected.
     *
     * @param src the original source expression
     */
    CoercedExpression(const Expression& src) : coerced(src) {}

    /**
     * Represents a successful coercion that led to a new expression
     * different from the source expression.
     *
     * @param src the original source expression's type
     * @param coerced the resulting expression that *src* was coerced to
     */
    CoercedExpression(const Type& src, Expression coerced)
        : coerced(coerced), nexpr(coerced), consider_type_changed(src.typename_() != coerced.type().typename_()) {}

    /** Represents an unsuccessful coercion. */
    CoercedExpression() = default;

    /**
     * Represents an unsuccessful coercion, carrying an error message along
     * explaining why it failed.
     */
    CoercedExpression(const result::Error& error) : coerced(error) {}
};

/**
 * Coerces an expression to a given target type. This returns a struct with
 * fields that provide result of the coercion, along with additional meta
 * information. Depending on the coercion style, a coerced expression may be
 * the exact same expression as passed in if types match sufficiently.
 *
 * @note This function does not actually *perform* the coercion, it just
 * returns an AST of the specified target type that will let the compiler
 * later carry out the coercion (usually that'll be a `expression::Coerced``
 * node).
 *
 * @param e expression to coerce
 * @param dst target type
 * @param style coercion style to use, given as a bitmask of any style
 * specifiers that apply
 * @return the *result* will evaluate to true if coercion was successful; if
 * so, the contained fields will provide more information
 */
CoercedExpression coerceExpression(const Expression& e, const Type& dst,
                                   bitmask<CoercionStyle> style = CoercionStyle::TryAllForAssignment, bool lhs = false);

/**
 * Coerces an expression to a given target type. This returns a struct with
 * fields that provide result of the coercion, along with additional meta
 * information. Depending on the coercion style, a coerced expression may be
 * the exact same expression as passed in if types match sufficiently.
 *
 * @note This function does not actually *perform* the coercion, it just
 * returns an AST of the specified target type that will let the compiler
 * later carry out the coercion (usually that'll be a `expression::Coerced``
 * node).
 *
 * @param e expression to coerce
 * @param src explicitly specified source type; this can be different from
 * the type of *e* and will be used instead of that
 * @param dst target type
 * @param style coercion style to use, given as a bitmask of any style
 * specifiers that apply
 * @return the *result* will evaluate to true if coercion was successful; if
 * so, the contained fields will provide more information
 */
CoercedExpression coerceExpression(const Expression& e, const Type& src_, const Type& dst_,
                                   bitmask<CoercionStyle> style = CoercionStyle::TryAllForAssignment, bool lhs = false);

/**
 * Matches a set of expressions against a set of operands, coercing them as
 * needed. This takes into account specifics of the operands, such as them
 * being optional or having defaults.
 *
 * @param exprs source expressions to match against the operands
 * @param operands operands to match against
 * @param style coercion style to use for each expression's coercion to its
 * operand, given as a bitmask of any style
 * specifiers that apply
 * @return If successful, a pair with a boolean as its 1st argument that
 * indicates whether any of the expressions was changed; and as its 2nd
 * element, the coerced expressions now matching the operands. The returned
 * vector will have defaults filled in for missing expressions where
 * available (missing expressions for optional operands without defaults will
 * remain left out). If unsuccessful, an error.
 */
Result<std::pair<bool, std::vector<Expression>>> coerceOperands(const hilti::node::Range<Expression>& exprs,
                                                                const std::vector<operator_::Operand>& operands,
                                                                bitmask<CoercionStyle> style);

/**
 * Coerces a constructor to a given target type. This returns the coerced
 * constructor, now of the new type. If the constructor is already of the
 * right type, it will just be returned back.
 *
 * @param c ctor to coerce
 * @param dst target type
 * @param style coercion style to use
 * @return if the coercion was successful, the returned new value (which may be the same as the old)
 */
Result<Ctor> coerceCtor(Ctor c, const Type& dst, bitmask<CoercionStyle> style = CoercionStyle::TryAllForAssignment);

/**
 * Coerces a source type to a given target type. This returns the coerced
 * type. If the type is already of the right type, it will just be returned
 *  back.
 *
 * @param c ctor to coerce
 * @param dst target type
 * @param style coercion style to use
 * @return if the coercion was successful, the returned new value (which may be the same as the old)
 */
Result<Type> coerceType(const Type& src_, const Type& dst_,
                        bitmask<CoercionStyle> style = CoercionStyle::TryAllForAssignment);

namespace detail {
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
std::optional<Ctor> coerceCtor(Ctor c, const Type& dst, bitmask<CoercionStyle> style);
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
std::optional<Type> coerceType(Type t, const Type& dst, bitmask<CoercionStyle> style);
} // namespace detail

} // namespace hilti
