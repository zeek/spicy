// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

namespace hilti::rt {

struct Context;

/**
 * Initializes the HILTI run-time library. This must be called once at
 * startup before any other libhilti functionality can be used.
 */
extern void init();

/**
 * Shuts down the run-time library, freeing all resources. Once executed, no
 * libhilti functionality can be used anymore.
 */
extern void done();

/** Returns true if init() has already been called. */
extern bool isInitialized();

/** Execute any functions registered through `RegisterManualPreInit`. */
extern void executeManualPreInits();

namespace detail {

/** A HILTI module registered with the runtime. The HILTI code generator creates code to register an instance of this
 * for every module it compiles. */
struct HiltiModule {
    const char* name{};              /**< name of the HILTI module; for informational purposes */
    const char* id = nullptr;        /**< unique identifier for the module */
    void (*init_module)() = nullptr; /**< callback for executing any top-level module code when the runtime library is
                                being initialized; null if not needed */
    void (*init_globals)(hilti::rt::Context* ctx) =
        nullptr; /**< callback to initialize the module's globals in a freshly allocated context; null if not needed */
    void (*destroy_globals)(hilti::rt::Context* ctx) =
        nullptr; /**< callback to destroy the module's globals at termination; null if not needed */
    unsigned int* globals_idx = nullptr; /**< pointer to an integer storing the modules' index in the context-wide
                                            globals array; valid only if dynamic globals are in use */
};

/** Entry point for the generated code to register a compiled HILTI module with the runtime */
extern void registerModule(HiltiModule module);

/**
 * Macro to schedule a global function to be called at startup time. Execution
 * will happen either automatically through a static constructor (default), or
 * if `HILTI_MANUAL_PREINIT` is defined, be triggered through a call to
 * `executeCustomPreInits()`.
 */
#ifdef HILTI_MANUAL_PREINIT
#define HILTI_PRE_INIT(func) static ::hilti::rt::detail::RegisterManualPreInit __pre_init_##__COUNTER__(func);
#else
#define HILTI_PRE_INIT(func) static ::hilti::rt::detail::ExecutePreInit __pre_init_##__COUNTER__(func);
#endif

/** Helper class to execute a global function at startup time through a global constructor. */
class ExecutePreInit {
public:
    ExecutePreInit(void (*f)()) { (*f)(); }
};

/** Helper class to register a global function to execute through `executeCustomPreInits`. */
class RegisterManualPreInit {
public:
    RegisterManualPreInit(void (*f)());
};

} // namespace detail

} // namespace hilti::rt
