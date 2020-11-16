// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/init.h"

#include <sys/resource.h>
#include <unistd.h>

#include <cinttypes>
#include <clocale>

#include <hilti/rt/configuration.h>
#include <hilti/rt/context.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

void hilti::rt::init() {
    if ( globalState()->runtime_is_initialized )
        return;

    if ( ! setlocale(LC_CTYPE, "") )
        fatalError("cannot set locale");

    if ( ! globalState()->configuration )
        globalState()->configuration = std::make_unique<hilti::rt::Configuration>();

    if ( auto debug_out = globalState()->configuration->debug_out )
        globalState()->debug_logger = std::make_unique<hilti::rt::detail::DebugLogger>(*debug_out);
    else
        globalState()->debug_logger = std::make_unique<hilti::rt::detail::DebugLogger>("/dev/stderr");

    globalState()->debug_logger->enable(globalState()->configuration->debug_streams);

    HILTI_RT_DEBUG("libhilti", "initializing runtime");

    globalState()->master_context = std::make_unique<Context>(vthread::Master);
    context::detail::set(globalState()->master_context.get());

    for ( const auto& m : globalState()->hilti_modules ) {
        if ( m.init_globals ) {
            HILTI_RT_DEBUG("libhilti", fmt("initializing globals for module %s", m.name));
            (*m.init_globals)(context::detail::master());
        }
    }

    for ( const auto& m : globalState()->hilti_modules ) {
        if ( m.init_module ) {
            HILTI_RT_DEBUG("libhilti", fmt("executing initialization code for module %s", m.name));
            (*m.init_module)();
        }
    }

    if ( ! globalState()->main_co ) {
        // Clear any coroutines scheduled in a previous run.
        Fiber::reset();
    }

    globalState()->runtime_is_initialized = true;
    globalState()->resource_usage_init = resource_usage();
}

void hilti::rt::done() {
    if ( ! globalState() )
        return;

    HILTI_RT_DEBUG("libhilti", "shutting down runtime");

    if ( globalState()->configuration && globalState()->configuration->report_resource_usage ) {
        auto stats = rt::resource_usage();
        std::cerr << fmt("# user_time=%.6f sys_time=%.6f memory=%" PRIu64 "\n", stats.user_time, stats.system_time,
                         stats.memory_heap);
    }

    delete __global_state; // NOLINT (cppcoreguidelines-owning-memory)
    __global_state = nullptr;
    context::detail::set(nullptr);
}

bool hilti::rt::isInitialized() { return globalState()->runtime_is_initialized; }

void hilti::rt::detail::registerModule(HiltiModule module) {
    HILTI_RT_DEBUG("libhilti", fmt("registering module %s", module.name));

    if ( module.globals_idx )
        *module.globals_idx = globalState()->hilti_modules.size();

    globalState()->hilti_modules.emplace_back(std::move(module));
}
