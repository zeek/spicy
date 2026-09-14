// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cassert>
#include <utility>
#include <vector>

namespace spicy::detail::pir::ir {

/** A flat, append-only arena. References from `get()` may be invalidated by `add()`. */
template<typename T, typename IdT>
class Arena {
public:
    using Id = IdT;
    using value_type = T;

    Id add(T value) {
        _entries.push_back(std::move(value));
        return Id{static_cast<uint32_t>(_entries.size() - 1)};
    }

    bool isValid(Id id) const noexcept { return id.isSet() && id.index < _entries.size(); }

    const T& get(Id id) const {
        assert(isValid(id));
        return _entries[id.index];
    }

    T& get(Id id) {
        assert(isValid(id));
        return _entries[id.index];
    }

    size_t size() const noexcept { return _entries.size(); }

    auto begin() const { return _entries.begin(); }
    auto end() const { return _entries.end(); }

private:
    std::vector<T> _entries;
};

} // namespace spicy::detail::pir::ir
