// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <string>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/**
 * AST node for a generic type defined just by the runtime library. A library
 * type remains mostly opaque to the HILTI language and can't be access
 * directly from a HILTI program. Usually, there'll be HILTI-side typedef
 * making it accessible in the `hilti::*` namespace. HILTI assumes the
 * library type to be mutable.
 */
class Library : public UnqualifiedType {
public:
    const std::string& cxxName() const { return _cxx_name; }

    std::string_view typeClass() const final { return "library"; }

    bool isAllocable() const final { return true; }
    bool isMutable() const final { return true; }

    node::Properties properties() const final {
        auto p = node::Properties{{"cxx_name", _cxx_name}};
        return UnqualifiedType::properties() + p;
    }

    static auto create(ASTContext* ctx, const std::string& cxx_name, Meta meta = {}) {
        return std::shared_ptr<Library>(new Library(ctx, cxx_name, std::move(meta)));
    }

private:
    Library(ASTContext* ctx, std::string cxx_name, Meta meta)
        : UnqualifiedType(ctx, NodeTags, {util::fmt("library(%s)", cxx_name)}, std::move(meta)),
          _cxx_name(_normalize(std::move(cxx_name))) {}

    HILTI_NODE_1(type::Library, UnqualifiedType, final);

    std::string _normalize(std::string name) {
        if ( util::startsWith(name, "::") )
            return name;
        else
            return std::string("::") + name;
    }

    std::string _cxx_name;
};

} // namespace hilti::type
