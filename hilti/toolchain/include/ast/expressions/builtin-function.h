// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>

namespace hilti::expression {

/** AST node representing a builtin function call. */
class BuiltinFunction : public NodeBase, public trait::isExpression {
public:
    /** Construct a builtin function call node.
     *
     * @param name the name of the function on the HILTI side
     * @param cxxname the name of the wrapped C++ function
     * @param type the return type of the function
     * @param parameters parameters of the function
     * @param arguments arguments to the function call
     * @param m meta information for the function call
     */
    BuiltinFunction(std::string name, std::string cxxname, hilti::Type type,
                    const std::vector<declaration::Parameter>& parameters, std::vector<Expression> arguments,
                    Meta m = Meta())
        : NodeBase(nodes(std::move(type), parameters, std::move(arguments)), std::move(m)),
          _name(std::move(name)),
          _cxxname(std::move(cxxname)),
          _num_parameters(static_cast<int>(parameters.size())) {}

    auto arguments() const { return children<Expression>(_num_parameters + 1, -1); }
    auto parameters() const { return children<declaration::Parameter>(1, _num_parameters); }
    const auto& cxxname() const { return _cxxname; }
    const auto& name() const { return _name; }

    void setArguments(std::vector<hilti::Expression> args) {
        children().clear();

        for ( auto& a : args )
            children().emplace_back(std::move(a));
    }

    friend bool operator==(const BuiltinFunction& lhs, const BuiltinFunction& rhs) {
        return lhs._cxxname == rhs._cxxname && lhs.type() == rhs.type() && lhs.parameters() == rhs.parameters() &&
               lhs.arguments() == rhs.arguments();
    }

    /** Implements `Expression` interface. */
    const Type& type() const { return child<hilti::Type>(0); };
    /** Implements `Expression` interface. */
    bool isConstant() const { return false; }
    /** Implements `Expression` interface. */
    auto isEqual(const Expression& other) const { return node::isEqual(this, other); }
    /** Implements `Expression` interface. */
    auto isLhs() const { return false; }
    /** Implements `Expression` interface. */
    auto isTemporary() const { return true; }
    /** Implements `Expression` interface. */
    auto properties() const { return node::Properties{{"name", _name}}; }

private:
    std::string _name;
    std::string _cxxname;
    int _num_parameters = 0;
};

} // namespace hilti::expression
