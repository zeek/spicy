// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <memory>
#include <vector>

#include <hilti/rt/configuration.h>
#include <hilti/rt/context.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/profiler.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

void hilti::rt::init() {
    if ( globalState()->runtime_is_initialized )
        return;

    if ( ! configuration::detail::__configuration )
        configuration::detail::__configuration = std::make_unique<hilti::rt::Configuration>();

    if ( ! configuration::detail::unsafeGet().debug_streams.empty() ) {
        if ( auto debug_out = configuration::detail::unsafeGet().debug_out )
            globalState()->debug_logger = std::make_unique<hilti::rt::detail::DebugLogger>(*debug_out);
        else
            globalState()->debug_logger = std::make_unique<hilti::rt::detail::DebugLogger>("/dev/stderr");

        globalState()->debug_logger->enable(configuration::detail::unsafeGet().debug_streams);
    }

    HILTI_RT_DEBUG("libhilti", "initializing runtime");

    globalState()->master_context = std::make_unique<Context>(vthread::Master);
    context::detail::set(globalState()->master_context.get());

    if ( configuration::get().enable_profiling )
        profiler::detail::init();

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

    globalState()->runtime_is_initialized = true;
    globalState()->resource_usage_init = resource_usage();
}

void hilti::rt::done() {
    if ( ! __global_state )
        return;

    HILTI_RT_DEBUG("libhilti", "shutting down runtime");

    if ( configuration::detail::__configuration && configuration::detail::__configuration->report_resource_usage ) {
        auto stats = rt::resource_usage();
        std::cerr << fmt("# user_time=%.6f sys_time=%.6f memory=%" PRIu64 "\n", stats.user_time, stats.system_time,
                         stats.memory_heap);
    }

    profiler::detail::done();

    for ( const auto& m : globalState()->hilti_modules ) {
        if ( m.destroy_globals ) {
            HILTI_RT_DEBUG("libhilti", fmt("destroying globals for module %s", m.name));
            (*m.destroy_globals)(context::detail::master());
        }
    }

    delete __global_state; // NOLINT (cppcoreguidelines-owning-memory)
    __global_state = nullptr;
    context::detail::set(nullptr);
}

bool hilti::rt::isInitialized() { return __global_state && __global_state->runtime_is_initialized; }

void hilti::rt::detail::registerModule(HiltiModule module) {
    // Check whether the module was previously registered.
    for ( const auto& m : globalState()->hilti_modules ) {
        if ( std::strcmp(m.name, module.name) == 0 && std::strcmp(m.id, module.id) == 0 ) {
            HILTI_RT_DEBUG("libhilti",
                           fmt("skipping registration of module %s since the module was registered previously",
                               module.name));
            return;
        }
    }

    HILTI_RT_DEBUG("libhilti", fmt("registering module %s", module.name));

    if ( module.globals_idx )
        *module.globals_idx = globalState()->hilti_modules.size();

    globalState()->hilti_modules.emplace_back(module);
}

static std::unique_ptr<std::vector<void (*)()>> _registered_preinit_functions;

RegisterManualPreInit::RegisterManualPreInit(void (*f)()) {
    if ( ! _registered_preinit_functions )
        _registered_preinit_functions = std::make_unique<std::vector<void (*)()>>();

    _registered_preinit_functions->emplace_back(f);
}

void hilti::rt::executeManualPreInits() {
    if ( ! _registered_preinit_functions )
        return;

    for ( const auto& f : *_registered_preinit_functions )
        (*f)();

    _registered_preinit_functions.reset();
}
