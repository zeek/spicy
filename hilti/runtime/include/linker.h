// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#define HILTI_EXPORT __attribute__((visibility("default")))
#define HILTI_HIDDEN __attribute__((visibility("hidden")))
#define HILTI_WEAK __attribute__((weak))
