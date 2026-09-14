// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>

namespace spicy::detail::pir::ir {

/** A typed, package-local arena index. */
template<typename Tag>
struct ID {
    static constexpr uint32_t Invalid = UINT32_MAX;

    uint32_t index = Invalid;

    constexpr bool isSet() const { return index != Invalid; }

    friend constexpr bool operator==(ID, ID) = default;
};

} // namespace spicy::detail::pir::ir
