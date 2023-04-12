// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.
//
// This file is included at the beginning of each generated
// C++ file to setup compiler options.

#pragma once

// Options for both GCC and clang
#pragma GCC diagnostic ignored "-Wunused"
#pragma GCC diagnostic ignored "-Winvalid-offsetof" // our type info infrastructure needs this

#if defined(__clang__)
// Clang-specific options.
#pragma clang diagnostic ignored "-Wtautological-compare"
#elif defined(__GNUC__) // note that clang defines this as well
// GCC-specific options
#endif
