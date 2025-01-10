// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <string>

#include <hilti/ast/meta.h>
#include <hilti/base/id-base.h>
#include <hilti/base/util.h>

namespace hilti {

/** Represents an identifier. */
class ID : public detail::IDBase<ID> {
public:
    using IDBase::IDBase;
};

inline std::ostream& operator<<(std::ostream& out, const ID& id) {
    out << std::string(id);
    return out;
}

} // namespace hilti

namespace std {
template<>
struct hash<hilti::ID> {
    std::size_t operator()(const hilti::ID& id) const { return hash<std::string>()(id); }
};
} // namespace std
