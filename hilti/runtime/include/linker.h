// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#if defined(_MSC_VER)
#define HILTI_EXPORT __declspec(dllexport)
#define HILTI_HIDDEN
#define HILTI_WEAK __declspec(selectany)
#else
#define HILTI_EXPORT __attribute__((visibility("default")))
#define HILTI_HIDDEN __attribute__((visibility("hidden")))
#define HILTI_WEAK __attribute__((weak))
#endif
