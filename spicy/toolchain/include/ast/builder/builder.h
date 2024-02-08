// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/builder/builder.h>

#include <spicy/ast/builder/node-factory.h>
#include <spicy/ast/forward.h>

namespace spicy {

/**
 * Base class for extended builder merging the HILTI-side API with the
 * Spicy-side factory methods.
 */
class BuilderBase : public hilti::Builder, public spicy::builder::NodeFactory {
public:
    BuilderBase(ASTContext* ctx) : hilti::Builder(ctx), spicy::builder::NodeFactory(ctx) {}
    BuilderBase(hilti::Builder* builder) : hilti::Builder(builder), builder::NodeFactory(builder->context()) {}

    BuilderBase(ASTContext* context, std::shared_ptr<hilti::statement::Block> block)
        : hilti::Builder(context, std::move(block)), spicy::builder::NodeFactory(context) {}

    using hilti::Builder::context;
};

using Builder = hilti::ExtendedBuilderTemplate<BuilderBase>;
using BuilderPtr = std::shared_ptr<Builder>;

namespace builder {

/**
 * Parses a string as an expression in Spicy syntax.
 *
 * @param builder the builder to use for parsing
 * @param expr the expression to parse
 * @param meta meta information to attach to the resulting expression
 */
hilti::Result<hilti::ExpressionPtr> parseExpression(Builder* builder, const std::string& expr, const hilti::Meta& meta);

} // namespace builder
} // namespace spicy
