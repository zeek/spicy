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
    using Base = detail::IDBase<ID>;

    /** Creates an empty ID. */
    ID() {}

    /** Creates an ID from an (not normalized) string. */
    ID(const char* s) : Base(s) {}
    explicit ID(std::string_view s) : Base(s) {}

    /**
     * Creates an ID from a string that's already normalized. The assumption is
     * that the input string is the output of a prior `str()` call on an
     * existing ID object.
     */
    ID(std::string_view s, AlreadyNormalized n) : Base(s, n) {}

    /** Concatenates multiple strings into a single ID, separating them with `::`. */
    template<typename... T, typename enable = std::enable_if_t<(... && std::is_convertible_v<T, std::string_view>)>>
    explicit ID(const T&... s) : Base(s...) {}

    /** Concatenates multiple strings into a single ID, separating them with `::`. */
    ID(std::initializer_list<std::string_view> x) : Base(x) {}

    ID(const Base& other) : Base(other) {}

    ID(Base&& other) noexcept : Base(other) {}
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
