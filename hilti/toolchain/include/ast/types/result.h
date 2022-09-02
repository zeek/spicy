// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>
#include <vector>

#include <hilti/ast/type.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/base/optional-ref.h>

namespace hilti::type {

/** AST node for a "result" type. */
class Result : public TypeBase {
public:
    Result(Wildcard /*unused*/, Meta m = Meta()) : TypeBase({type::unknown}, std::move(m)), _wildcard(true) {}
    Result(Type ct, Meta m = Meta()) : TypeBase({std::move(ct)}, std::move(m)) {}

    optional_ref<const Type> dereferencedType() const override { return children()[0].as<Type>(); }

    bool operator==(const Result& other) const { return dereferencedType() == other.dereferencedType(); }

    bool isEqual(const Type& other) const override { return node::isEqual(this, other); }

    bool _isResolved(ResolvedState* rstate) const override {
        return type::detail::isResolved(dereferencedType(), rstate);
    }

    std::vector<Node> typeParameters() const override { return children(); }
    bool isWildcard() const override { return _wildcard; }

    node::Properties properties() const override { return node::Properties{}; }

    bool _isAllocable() const override { return true; }
    bool _isParameterized() const override { return true; }

    const std::type_info& typeid_() const override { return typeid(decltype(*this)); }

    HILTI_TYPE_VISITOR_IMPLEMENT

private:
    bool _wildcard = false;
};

} // namespace hilti::type
