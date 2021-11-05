// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

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

namespace detail {

/** A HILTI module registered with the runtime. The HILTI code generator creates code to register an instance of this
 * for every module it compiles. */
struct HiltiModule {
    const char* name{};              /**< name of the HILTI module; for informational purposes */
    const char* id = nullptr;        /**< unique identifier for the module */
    void (*init_module)() = nullptr; /**< callback for executing any top-level module code when the runtime library is
                                being initialized */
    void (*init_globals)(hilti::rt::Context* ctx) =
        nullptr; /**< callback to initialize the module's globals in a freshly allocated context */
    unsigned int* globals_idx =
        nullptr; /**< pointer to an integer storing the modules' index in the context-wide globals array */
};

/** Entry point for the generated code to register a compiled HILTI module with the runtime */
extern void registerModule(HiltiModule module);

/** Macro to schedule a global function to be called at startup time through a global constructor. */
#define HILTI_PRE_INIT(func) static ::hilti::rt::detail::ExecutePreInit __pre_init_##__COUNTER__(func);

/** Helper class to execute a global function at startup time through a global constructor. */
class ExecutePreInit {
public:
    ExecutePreInit(void (*f)()) { (*f)(); }
};

} // namespace detail

} // namespace hilti::rt
