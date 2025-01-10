// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string_view>
#include <utility>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/unknown.h>

namespace hilti::type {

namespace function {

using Parameter = declaration::Parameter;
using Parameters = declaration::Parameters;

/**
 * A function's flavor differentiates between a set of "function-like"
 * language element.
 */
enum class Flavor {
    Hook,    /**< a hook */
    Method,  /**< a struct method */
    Standard /**< a normal function */
};

namespace detail {
constexpr util::enum_::Value<Flavor> Flavors[] = {
    {Flavor::Hook, "hook"},
    {Flavor::Method, "method"},
    {Flavor::Standard, "standard"},
};
} // namespace detail

constexpr auto to_string(Flavor f) { return util::enum_::to_string(f, detail::Flavors); }

namespace flavor {
constexpr auto from_string(std::string_view s) { return util::enum_::from_string<Flavor>(s, detail::Flavors); }
} // namespace flavor

} // namespace function

/** AST node for a `function` type. */
class Function : public UnqualifiedType {
public:
    auto result() const { return child<QualifiedType>(0); }
    auto flavor() const { return _flavor; }
    const auto& functionNameForPrinting() const { return _id; }

    std::string_view typeClass() const final { return "function"; }

    node::Set<type::function::Parameter> parameters() const final {
        node::Set<type::function::Parameter> result;
        for ( auto&& p : children<function::Parameter>(1, {}) )
            result.push_back(p);

        return result;
    }

    bool isResolved(node::CycleDetector* cd) const final;

    void setResultType(ASTContext* ctx, QualifiedType* t) { setChild(ctx, 0, t); }
    void setFunctionNameForPrinting(ID id) { _id = std::move(id); } // just for operating printing
    void setParameters(ASTContext* ctx, const declaration::Parameters& params) {
        removeChildren(1, {});
        addChildren(ctx, params);
    }

    node::Properties properties() const final {
        auto p = node::Properties{{"flavor", to_string(_flavor)}};
        return UnqualifiedType::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, QualifiedType* result, const declaration::Parameters& params,
                       function::Flavor flavor = function::Flavor::Standard, Meta meta = {}) {
        return ctx->make<Function>(ctx, flatten(result, params), flavor, std::move(meta));
    }

    static auto create(ASTContext* ctx, Wildcard _, const Meta& m = Meta()) {
        return ctx->make<Function>(ctx, Wildcard(),
                                   {QualifiedType::create(ctx, type::Unknown::create(ctx, m), Constness::Const)}, m);
    }

protected:
    Function(ASTContext* ctx, Nodes children, function::Flavor flavor, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {}, std::move(children), std::move(meta)), _flavor(flavor) {}

    Function(ASTContext* ctx, Wildcard _, Nodes children, Meta meta)
        : UnqualifiedType(ctx, NodeTags, Wildcard(), {"function(*)"}, std::move(children), std::move(meta)),
          _flavor(function::Flavor::Standard) {}

    HILTI_NODE_1(type::Function, UnqualifiedType, final);

private:
    function::Flavor _flavor;
    ID _id;
};

/**
 * Returns true if two function types are equivalent, even if not
 * identical. This for example allows parameter ID to be different.
 */
inline bool areEquivalent(Function* f1, Function* f2) {
    if ( ! type::same(f1->result(), f2->result()) )
        return false;

    auto p1 = f1->parameters();
    auto p2 = f2->parameters();
    return std::equal(std::begin(p1), std::end(p1), std::begin(p2), std::end(p2),
                      [](const auto& p1, const auto& p2) { return areEquivalent(p1, p2); });
}


} // namespace hilti::type
