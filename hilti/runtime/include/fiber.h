// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once
#include <any>
#include <csetjmp>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <hilti/rt/exception.h>
#include <hilti/rt/lambda.h>

extern "C" {
// libtask introduces "Context" into the global scope, which leads
// to ambiguities. As we don't need it, we just hide it.
#define Context __libtask__Context
#include <hilti/rt/3rdparty/libtask/taskimpl.h>
#undef Context
// Undef macros that libtask defines.
#undef print
#undef nil

void _Trampoline(unsigned int y, unsigned int x);
}

namespace hilti::rt {

namespace detail {
class Fiber;
} // namespace detail

namespace resumable {
/** Abstract handle providing access to a currently active function running inside a fiber.  */
using Handle = detail::Fiber;
} // namespace resumable

namespace detail {

/**
 * A fiber implements a co-routine that can at any time yield control back to
 * the caller, to be resumed later. This is the internal class implementing
 * the main functionalty. It's used by `Resumable`, which provides the
 * external interface.
 */
class Fiber {
public:
    Fiber();
    ~Fiber();

    Fiber(const Fiber&) = delete;
    Fiber(Fiber&&) = delete;
    Fiber& operator=(const Fiber&) = delete;
    Fiber& operator=(Fiber&&) = delete;

    void init(Lambda<std::any(resumable::Handle*)> f) {
        _result = {};
        _exception = nullptr;
        _function = std::move(f);
    }

    void run();
    void yield();
    void resume();
    void abort();

    auto&& result() { return std::move(_result); }
    std::exception_ptr exception() const { return _exception; }

    static std::unique_ptr<Fiber> create();
    static void destroy(std::unique_ptr<Fiber> f);
    static void primeCache();
    static void reset();

    struct Statistics {
        uint64_t total;
        uint64_t current;
        uint64_t cached;
        uint64_t max;
        uint64_t initialized;
    };

    static Statistics statistics();

    // Size of stack for each fiber.
    static constexpr unsigned int StackSize = 327680;

    // Max. number of fibers cached for reuse.
    static constexpr unsigned int CacheSize = 100;

private:
    friend void ::_Trampoline(unsigned int y, unsigned int x);
    enum class State { Init, Running, Aborting, Yielded, Idle, Finished };

    /** Code to run just before we switch to a fiber. */
    void _startSwitchFiber(const char* tag, const void* stack_bottom = nullptr, size_t stack_size = 0);

    /** Code to run just after we have switched to a fiber. */
    void _finishSwitchFiber(const char* tag);

    State _state{State::Init};
    std::optional<Lambda<std::any(resumable::Handle*)>> _function;
    std::optional<std::any> _result;
    std::exception_ptr _exception;

    ucontext_t _uctx{};
    jmp_buf _fiber{};
    jmp_buf _trampoline{};
    jmp_buf _parent{};

#ifdef HILTI_HAVE_SANITIZER
    struct {
        const void* prev_bottom = nullptr;
        size_t prev_size = 0;
        void* fake_stack = nullptr;
    } _asan;
#endif

    // TODO: Usage of these isn't thread-safe. Should become "atomic" and
    // move into global state.
    inline static uint64_t _total_fibers;
    inline static uint64_t _current_fibers;
    inline static uint64_t _max_fibers;
    inline static uint64_t _initialized; // number of trampolines run
};

extern void yield();

} // namespace detail

/**
 * Executor for a function that may yield control back to the caller even
 * before it's finished. The caller can then later resume the function to
 * continue its operation.
 */
class Resumable {
public:
    /**
     * Creates an instance initialied with a function to execute. The
     * function can then be started by calling `run()`.
     *
     * @param f function to be executed
     */
    template<typename Function, typename = std::enable_if_t<std::is_invocable<Function, resumable::Handle*>::value>>
    Resumable(Function f) : _fiber(detail::Fiber::create()) {
        _fiber->init(std::move(f));
    }

    Resumable(Resumable&& r) noexcept : _fiber(std::move(r._fiber)), _result(std::move(r._result)) {}

    Resumable& operator=(Resumable&& other) noexcept {
        _fiber = std::move(other._fiber);
        _result = std::move(other._result);
        return *this;
    }

    Resumable() = default;
    Resumable(const Resumable& r) = delete;
    Resumable& operator=(const Resumable& other) = delete;

    ~Resumable() {
        if ( _fiber )
            detail::Fiber::destroy(std::move(_fiber));
    }

    /** Starts execution of the function. This must be called only once. */
    void run();

    /** When a function has yielded, resumes its operation. */
    void resume();

    /** When a function has yielded, abort its operation without resuming. */
    void abort();

    /** Returns a handle to the currently running function. */
    resumable::Handle* handle() { return _fiber.get(); }

    /**
     * Returns the function's result once it has completed. Must not be
     * called before completion; check with `operator bool()` first.
     */
    template<typename Result>
    Result get() const {
        assert(static_cast<bool>(_result));

        if constexpr ( std::is_same<Result, void>::value )
            return;

        try {
            return std::any_cast<Result>(*_result);
        } catch ( const std::bad_any_cast& ) {
            throw InvalidArgument("mismatch in result type");
        }
    }

    /**
     * Returns true if the function has completed. If so, `get()` can be
     * called to retrieve its result.
     */
    explicit operator bool() const { return static_cast<bool>(_result); }

private:
    void yielded();

    void checkFiber(const char* location) const {
        if ( ! _fiber )
            throw std::logic_error(std::string("fiber not set in ") + location);
    }

    std::unique_ptr<detail::Fiber> _fiber;
    std::optional<std::any> _result;
};

namespace fiber {

/**
 * Executes a resumable function. This is a utility wrapper around
 * `Resumable` that immediately starts the function.
 */
template<typename Function>
auto execute(Function f) {
    Resumable r(std::move(f));
    r.run();
    return r;
}

} // namespace fiber
} // namespace hilti::rt
