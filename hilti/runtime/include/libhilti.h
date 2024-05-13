// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

// Do not use "#pragma once here". We use this file as top-level for header
// pre-compilation, and GCC doesn't like that there.
// See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=64117
#ifndef HILTI_RUNTIME_LIBHILTI_H
#define HILTI_RUNTIME_LIBHILTI_H

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/autogen/version.h>
#include <hilti/rt/configuration.h>
#include <hilti/rt/context.h>
#include <hilti/rt/deferred-expression.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/fiber-check-stack.h>
#include <hilti/rt/hilti.h>
#include <hilti/rt/init.h>
#include <hilti/rt/library.h>
#include <hilti/rt/linker.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/profiler.h>
#include <hilti/rt/result.h>
#include <hilti/rt/safe-int.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/all.h>
#include <hilti/rt/util.h>

using namespace hilti::rt::bytes::literals; // NOLINT (google-global-names-in-headers)

#endif
