// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/rt/3rdparty/ArticleEnumClass-v2/EnumClass.h>

#include <hilti/ast/forward.h>
#include <hilti/base/result.h>

namespace hilti::detail::constant_folder {

/** Style options for constant folding. */
enum class Style {
    /** Default style with no special options enabled. */
    Default = 0U,

    /** Fold constant ternary expressions. By default, these will not be folded. */
    FoldTernaryOperator = (1U << 2U),

    /** Inline boolean constants. By default, these will not be inlined. */
    InlineBooleanConstants = (1U << 1U),

    /**
     * Inline the magic feature constants used by the optimizer. By default,
     * feature constant will not be inlined.
     */
    InlineFeatureConstants = (1U << 0U),
};

/**
 * Folds an expression into a constant value if that's possible.
 *
 * If the function returns an error, that does not necessarily mean that the
 * expression is not representing a constant value, but only that we aren't
 * able to compute it (yet).
 *
 * @param builder builder to use for constructing any new AST nodes
 * @param expr expression to fold
 * @param style style options influencing the folding process
 * @return folded constant constructor, or an error if folding was not possible
 */
Result<Ctor*> foldExpression(Builder* builder, Expression* expr, bitmask<Style> style = Style::Default);

/**
 * Fold all expressions found inside a subtree of the AST into constant values
 * wherever that is possible.
 *
 * @param builder builder to use for constructing any new AST nodes
 * @param node root of the AST subtree to process
 * @param style style options influencing the folding process
 * @return true if any changes were made
 */
bool fold(Builder* builder, Node* node, bitmask<Style> style = Style::Default);

} // namespace hilti::detail::constant_folder

enableEnumClassBitmask(hilti::detail::constant_folder::Style); // must be in global scope
