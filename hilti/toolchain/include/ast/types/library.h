// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/ast/type.h>

namespace hilti::type {

/**
 * AST node for a generic type defined just by the runtime library. A library
 * type remains mostly opaque to the HILTI language and can't be access
 * directly from a HILTI program. Usually, there'll be HILTI-side typedef
 * making it accessible in the `hilti::*` namespace. HILTI assumes the
 * library type to be mutable.
 */
class Library : public TypeBase {
public:
    Library(std::string cxx_name, Meta m = Meta());

    const std::string& cxxName() const { return _cxx_name; }
    bool operator==(const Library& other) const { return _cxx_name == other._cxx_name; }

    bool isEqual(const Type& other) const override {
        if ( other.cxxID() == _cxx_name )
            return true;

        return node::isEqual(this, other);
    }

    bool _isResolved(ResolvedState* rstate) const override { return true; }
    node::Properties properties() const override { return node::Properties{{"cxx_name", _cxx_name}}; }

    bool _isAllocable() const override { return true; }
    bool _isMutable() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    HILTI_TYPE_VISITOR_IMPLEMENT

private:
    std::string _cxx_name;
};

} // namespace hilti::type
