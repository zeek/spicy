// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/node.h>
#include <hilti/ast/type.h>

namespace hilti {
namespace expression {

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
                    std::vector<declaration::Parameter> parameters, std::vector<Expression> arguments, Meta m = Meta())
        : NodeBase(nodes(std::move(type), parameters, std::move(arguments)), std::move(m)),
          _name(std::move(name)),
          _cxxname(std::move(cxxname)),
          _num_parameters(parameters.size()) {}

    /** Implements `Expression` interface. */
    auto type() const { return child<hilti::Type>(0); };

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

    const auto& name() const { return _name; }

    const auto& cxxname() const { return _cxxname; }

    auto arguments() const { return childs<Expression>(_num_parameters + 1, -1); }

    const auto parameters() const { return childs<declaration::Parameter>(1, _num_parameters); }

    /**
     * Returns a new builtin function node with the arguments replaced.
     *
     * @param d original builtin function
     * @param args new arguments
     * @return new builtin function now that is equal to the original one but with the arguments replaced
     */
    static BuiltinFunction setArguments(const BuiltinFunction& d, std::vector<hilti::Expression> args) {
        auto x = Expression(d)._clone().as<BuiltinFunction>();

        x.childs().clear();

        for ( auto& a : args )
            x.childs().emplace_back(std::move(a));

        return x;
    }

    friend bool operator==(const BuiltinFunction& lhs, const BuiltinFunction& rhs) {
        return lhs._cxxname == rhs._cxxname && lhs.type() == rhs.type() && lhs.parameters() == rhs.parameters() &&
               lhs.arguments() == rhs.arguments();
    }

private:
    std::string _name;
    std::string _cxxname;
    size_t _num_parameters = 0;
};

} // namespace expression
} // namespace hilti
