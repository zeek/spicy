// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/builder/builder.h>
#include <spicy/compiler/detail/parser/driver.h>

using namespace spicy;

hilti::Result<hilti::ExpressionPtr> builder::parseExpression(Builder* builder, const std::string& expr,
                                                             const hilti::Meta& meta) {
    return detail::parser::parseExpression(builder, expr, meta);
}
