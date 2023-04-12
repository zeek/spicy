// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <utility>

#include <hilti/ast/node.h>
#include <hilti/base/id-base.h>
#include <hilti/base/util.h>

namespace hilti {

/** AST node representing an identifier. */
class ID : public detail::IDBase<ID>, public NodeBase, public util::type_erasure::trait::Singleton {
public:
    using detail::IDBase<ID>::IDBase;
    ID(std::string name, Meta m) : IDBase(std::move(name)), NodeBase(std::move(m)) {}
    ID() = default;

    /** Assignment from string without changing location information. */
    ID& operator=(const std::string& s) {
        IDBase::operator=(ID(s));
        return *this;
    }

    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{{"name", std::string(*this)}}; }
};

inline std::ostream& operator<<(std::ostream& out, const ID& id) {
    out << std::string(id);
    return out;
}

/** Creates an AST node representing a `ID`. */
inline Node to_node(ID i) { return Node(std::move(i)); }

} // namespace hilti

namespace std {
template<>
struct hash<hilti::ID> {
    std::size_t operator()(const hilti::ID& id) const { return hash<std::string>()(id); }
};
} // namespace std
