// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/statement.h>

namespace hilti::statement {

namespace comment {
enum class Separator { After, BeforeAndAfter, Before };
} // namespace comment

/** AST node for an comment that will be passed through code generation.. */
class Comment : public NodeBase, public hilti::trait::isStatement {
public:
    Comment(std::string comment, comment::Separator separator = comment::Separator::Before,
            const Meta& /* m */ = Meta())
        : _comment(std::move(comment)), _separator(separator) {}

    auto comment() const { return _comment; }
    auto separator() const { return _separator; }

    bool operator==(const Comment& other) const { return comment() == other.comment(); }

    /** Implements the `Statement` interface. */
    auto isEqual(const Statement& other) const { return node::isEqual(this, other); }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"comment", _comment}}; }

private:
    std::string _comment;
    comment::Separator _separator;
};

} // namespace hilti::statement
