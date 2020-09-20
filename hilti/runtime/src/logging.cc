// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/logging.h"

#include <hilti/rt/debug-logger.h>
#include <hilti/rt/util.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

#include <cstdlib>
#include <iostream>

#include <hilti/rt/util.h>

using namespace hilti::rt;

void hilti::rt::internalError(const std::string& msg) {
    std::cerr << fmt("[libhilti] Internal error: %s", msg) << std::endl;
    abort_with_backtrace();
}

void hilti::rt::fatalError(const std::string& msg) {
    std::cerr << fmt("[libhilti] Fatal error: %s", msg) << std::endl;
    exit(1);
}

void hilti::rt::warning(const std::string& msg) { std::cerr << fmt("[libhilti] Warning: %s", msg) << std::endl; }
