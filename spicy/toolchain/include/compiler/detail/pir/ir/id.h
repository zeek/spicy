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

// `TypeId` is shared by `declaration.h` (field types) and `package.h`/`opcode.h` (the type
// arena and its structural payload); defining it alongside the generic `ID` template avoids a
// header cycle between those two.
struct TypeTag {};
using TypeId = ID<TypeTag>;

} // namespace spicy::detail::pir::ir
