// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once
#include <sys/resource.h>

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <hilti/rt/context.h>
#include <hilti/rt/debug-logger.h>
#include <hilti/rt/init.h>
#include <hilti/rt/profiler-state.h>

// We collect all (or most) of the runtime's global state centrally. That's
// 1st good to see what we have (global state should be minimal) and 2nd
// helpful to ensure that JIT maps things correctly. Note that all code
// accessing any of this state is in charge of ensuring thread-safety itself.
// These globals are generally initialized through hilti::rt::init();
//
// TODO(robin): Accesses to global state are *not* completely thread-safe yet.

namespace hilti::rt {
struct Configuration;

namespace regexp::detail {
class CompiledRegExp;
} // namespace regexp::detail

} // namespace hilti::rt

namespace hilti::rt::detail {

/** Struct capturing all truly global runtime state. */
struct GlobalState {
    GlobalState() = default;
    ~GlobalState();

    GlobalState(const GlobalState&) = delete;
    GlobalState(GlobalState&&) = delete;
    GlobalState& operator=(const GlobalState&) = delete;
    GlobalState& operator=(GlobalState&&) = delete;

    /** True once `hilit::init()`` has finished. */
    bool runtime_is_initialized = false;

    /** True once `profiler::init()` has been called. */
    bool profiling_enabled = false;

    /** If not zero, `Configuration::abort_on_exception` is disabled. */
    int disable_abort_on_exceptions = 0;

    /** Resource usage at library initialization time. */
    ResourceUsage resource_usage_init;

    /** Profiler's global measurements. */
    std::unordered_map<std::string, profiler::detail::MeasurementState> profilers;

    /** Debug logger recording runtime diagnostics. */
    std::unique_ptr<hilti::rt::detail::DebugLogger> debug_logger;

    /** The context for the main thread. */
    std::unique_ptr<hilti::rt::Context> master_context;

    /**
     * List of HILTI modules registered with the runtime. This is filled through `registerModule()`, which in turn gets
     * called through a module's global constructors at initialization time.
     *
     * @note Must come last in this struct as destroying other fields may
     * still need this information.
     */
    std::vector<hilti::rt::detail::HiltiModule> hilti_modules;

    /** Cache of already compiled regular expressions. */
    std::unordered_map<std::string, std::shared_ptr<regexp::detail::CompiledRegExp>> regexp_cache;

    /** Cached C locale for use with C library functions. */
    std::optional<locale_t> c_locale;
};

/**
 * Pointer to the global state singleton. Do not access directly, use
 * `globalState()` instead.
 */
extern GlobalState* __global_state;

/** Creates the global state singleton. */
extern GlobalState* createGlobalState();

/**
 * Returns the global state singleton. This creates the state the first time
 * it's called.
 */
inline auto globalState() {
    if ( __global_state )
        return __global_state;

    return createGlobalState();
}

/**
 * Returns the current global configuration without checking if it's already
 * initialized. This is only safe to use if the runtime is already fully
 * initialized, and should be left to internal use only where performance
 * matters.
 */
inline const GlobalState* unsafeGlobalState() {
    assert(__global_state);
    return __global_state;
}

/** Returns the current context's array of HILTI global variables. */
inline auto hiltiGlobals() {
    assert(context::detail::current());
    return context::detail::current()->hilti_globals;
}

/**
 * Returns the current context's set of a  HILTI module's global variables.
 *
 * @param idx module's index inside the array of HILTI global variables;
 * this is determined by the HILTI linker
 */
template<typename T>
inline auto moduleGlobals(unsigned int idx) {
    const auto& globals = hiltiGlobals();

    assert(idx < globals.size());

    return std::static_pointer_cast<T>(globals[idx]);
}

/**
 * Initialized the current context's set of a HILTI module's global
 * variables.
 *
 * @param idx module's index inside the array of HILTI global variables;
 * this is determined by the HILTI linker
 */
template<typename T>
inline auto initModuleGlobals(unsigned int idx) {
    if ( context::detail::current()->hilti_globals.size() <= idx )
        context::detail::current()->hilti_globals.resize(idx + 1);

    context::detail::current()->hilti_globals[idx] = std::make_shared<T>();
}

} // namespace hilti::rt::detail
