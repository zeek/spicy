// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/**
 * AST node for a generic type defined just by the C++ runtime
 * library. A library type remains mostly opaque to the HILTI language
 * and can't be accessed directly from a HILTI program. Usually,
 * there'll be HILTI-side typedef making it accessible in the
 * `hilti::*` namespace. Depending on the specified constness, HILTI
 * assumes the C++-side library type to be either mutable or constant.
 */
class Library : public UnqualifiedType {
public:
    bool isConstant() const { return _constness == Constness::Const; }
    const std::string& cxxName() const { return _cxx_name; }

    std::string_view typeClass() const final { return "library"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

    node::Properties properties() const final {
        auto constness = (_constness == Constness::Const ? "true" : "false");
        auto p = node::Properties{{"const", constness}, {"cxx_name", _cxx_name}};
        return UnqualifiedType::properties() + std::move(p);
    }

    static auto create(ASTContext* ctx, Constness const_, std::string cxx_name, Meta meta = {}) {
        return ctx->make<Library>(ctx, const_, std::move(cxx_name), std::move(meta));
    }

private:
    Library(ASTContext* ctx, Constness const_, std::string cxx_name, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {util::fmt("library(%s)", cxx_name)}, std::move(meta)),
          _constness(const_),
          _cxx_name(_normalize(std::move(cxx_name))) {}

    HILTI_NODE_1(type::Library, UnqualifiedType, final);

    std::string _normalize(std::string name) {
        if ( util::startsWith(name, "::") )
            return name;
        else
            return std::string("::") + name;
    }

    Constness _constness = Constness::Const;
    std::string _cxx_name;
};

} // namespace hilti::type
