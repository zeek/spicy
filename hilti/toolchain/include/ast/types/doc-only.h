// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/type.h>

namespace hilti::type {

/**
 * AST node for a type that's only used for documentation purposes. This type
 * allows to carry a textual description of the a type over into
 * auto-generated documentation. If it's used anywhere else, it'll cause
 * trouble.
 */
class DocOnly : public TypeBase {
public:
    DocOnly(std::string desc, Meta m = Meta()) : TypeBase(std::move(m)), _description(std::move(desc)) {}

    auto description() const { return _description; }

    bool operator==(const DocOnly& /* other */) const { return false; }

    // Type interface.
    auto isEqual(const Type& other) const { return node::isEqual(this, other); }
    /** Implements the `Type` interface. */
    auto _isResolved(ResolvedState* rstate) const { return true; }
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

private:
    std::string _description;
};

} // namespace hilti::type
