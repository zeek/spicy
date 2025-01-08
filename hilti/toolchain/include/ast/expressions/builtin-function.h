// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/function.h>

namespace hilti::expression {

/** AST node representing a builtin function call. */
class BuiltInFunction : public Expression {
public:
    auto arguments() const { return children<Expression>(_num_parameters + 1, {}); }
    auto parameters() const { return children<declaration::Parameter>(1, _num_parameters); }
    const auto& cxxname() const { return _cxxname; }
    const auto& name() const { return _name; }

    QualifiedType* type() const final { return child<QualifiedType>(0); }

    node::Properties properties() const final {
        auto p = node::Properties{{"name", _name}, {"cxxname", _cxxname}};
        return Expression::properties() + std::move(p);
    }

    void setArguments(ASTContext* ctx, const Expressions& args) {
        removeChildren(_num_parameters + 1, {});
        addChildren(ctx, args);
    }

    /** Construct a builtin function call node.
     *
     * @param name the name of the function on the HILTI side
     * @param cxxname the name of the wrapped C++ function
     * @param type the return type of the function
     * @param parameters parameters of the function
     * @param arguments arguments to the function call
     * @param m meta information for the function call
     */
    static auto create(ASTContext* ctx, const std::string& name, const std::string& cxxname, QualifiedType* type,
                       const type::function::Parameters& parameters, const Expressions& arguments, Meta meta = {}) {
        return ctx->make<BuiltInFunction>(ctx, node::flatten(type, parameters, arguments), name, cxxname,
                                          static_cast<int>(parameters.size()), std::move(meta));
    }

protected:
    BuiltInFunction(ASTContext* ctx, Nodes children, std::string name, std::string cxxname, int num_parameters,
                    Meta meta)
        : Expression(ctx, NodeTags, std::move(children), std::move(meta)),
          _name(std::move(name)),
          _cxxname(std::move(cxxname)),
          _num_parameters(num_parameters) {}

    HILTI_NODE_1(expression::BuiltInFunction, Expression, final);

private:
    std::string _name;
    std::string _cxxname;
    int _num_parameters = 0;
};

} // namespace hilti::expression
