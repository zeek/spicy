// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
// This file is included at the beginning of each generated
// C++ file to setup compiler options.

#pragma once

#if __clang__
// Clang-specific options.
#pragma clang diagnostic ignored "-Wunused-comparison"
#pragma clang diagnostic ignored "-Wunused-value"
#pragma clang diagnostic ignored "-Winvalid-offsetof" // our type info infrastructure needs this
#endif

#if __GNUC__
// GCC-specific options.
#pragma GCC diagnostic ignored "-Winvalid-offsetof" // our type info infrastructure needs this
#endif
