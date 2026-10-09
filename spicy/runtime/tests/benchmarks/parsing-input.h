// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>
#include <string>

inline std::string bigEndian(std::uint64_t number) {
    char buffer[8];
    for ( int i = 0; i < 8; ++i )
        buffer[i] = static_cast<char>((number >> (56 - (8 * i))) & 0xFF);
    return std::string(buffer, sizeof(buffer));
}

inline std::string makeInput(std::uint64_t input_size) {
    return bigEndian(input_size) + std::string(input_size, 'A') + "END";
}
