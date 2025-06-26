// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/statement.h>

namespace hilti::statement {

namespace comment {
enum class Separator { After, BeforeAndAfter, Before };

namespace detail {
constexpr util::enum_::Value<Separator> Conventions[] = {
    {.value = Separator::After, .name = "after"},
    {.value = Separator::BeforeAndAfter, .name = "before-and-after"},
    {.value = Separator::Before, .name = "before"},
};
} // namespace detail

constexpr auto to_string(Separator cc) { return util::enum_::to_string(cc, detail::Conventions); }

} // namespace comment

/** AST node for an comment that will be passed through code generation.. */
class Comment : public Statement {
public:
    const auto& comment() const { return _comment; }
    auto separator() const { return _separator; }

    node::Properties properties() const final {
        auto p = node::Properties{{"comment", _comment}, {"separator", to_string(_separator)}};
        return Statement::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, std::string comment, comment::Separator separator = comment::Separator::Before,
                       Meta meta = {}) {
        return ctx->make<Comment>(ctx, {}, std::move(comment), separator, std::move(meta));
    }

protected:
    Comment(ASTContext* ctx, Nodes children, std::string comment, comment::Separator separator, Meta meta)
        : Statement(ctx, NodeTags, std::move(children), std::move(meta)),
          _comment(std::move(comment)),
          _separator(separator) {}

    HILTI_NODE_1(statement::Comment, Statement, final);

private:
    std::string _comment;
    comment::Separator _separator;
};

} // namespace hilti::statement
