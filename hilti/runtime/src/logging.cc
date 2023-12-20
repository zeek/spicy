// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/debug-logger.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

#include <cstdlib>
#include <iostream>
#include <string_view>

using namespace hilti::rt;

HILTI_THREAD_LOCAL const char* debug::detail::tls_location = nullptr;

void hilti::rt::internalError(std::string_view msg) {
    std::cerr << fmt("[libhilti] Internal error: %s", msg) << '\n';
    abort_with_backtrace();
}

void hilti::rt::fatalError(std::string_view msg) {
    std::cerr << fmt("[libhilti] Fatal error: %s", msg) << '\n';
    // We do a hard abort here, with no cleanup, because  ASAN may have trouble
    // terminating otherwise if the fiber stacks are still hanging out.
    _exit(1);
}

void hilti::rt::warning(std::string_view msg) { std::cerr << fmt("[libhilti] Warning: %s", msg) << '\n'; }
