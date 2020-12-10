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
#include <hilti/rt/util.h>

struct Fiber;

namespace hilti::rt {

namespace detail {
extern "C" {
void _Trampoline(void* argsp);
}

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
    Fiber(bool main_fiber = false);
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

    bool isMain() const { return _is_main; }

    bool isDone() {
        switch ( _state ) {
            case State::Running:
            case State::Yielded: return false;

            case State::Aborting:
            case State::Finished:
            case State::Idle:
            case State::Init:
                // All these mean we didn't recently run a function that could have
                // produced a result still pending.
                return true;
        }
        cannot_be_reached(); // For you, GCC.
    }

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
    static constexpr unsigned int StackSize = 327'680;

    // Max. number of fibers cached for reuse.
    static constexpr unsigned int CacheSize = 100;

private:
    friend void _Trampoline(void* argsp);
    enum class State { Init, Running, Aborting, Yielded, Idle, Finished };

    /** Code to run just before we switch to a fiber. */
    static void _startSwitchFiber(const char* tag, const void* stack_bottom = nullptr, size_t stack_size = 0);

    /** Code to run just after we have switched to a fiber. */
    static void _finishSwitchFiber(const char* tag);

    static void _switchTo(detail::Fiber* to);

    bool _is_main;
    State _state{State::Init};
    std::optional<Lambda<std::any(resumable::Handle*)>> _function;
    std::optional<std::any> _result;
    std::exception_ptr _exception;

    /** The underlying coroutine of this fiber. */
    std::unique_ptr<::Fiber> _fiber;

    /**
     * The coroutine this fiber yields to.
     *
     * This is typically the coroutine of the fiber which invoked `run` on this
     * coroutine.
     */
    Fiber* _caller = nullptr;

    // void* saved_stack = nullptr;

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

    Resumable() = default;
    Resumable(const Resumable& r) = delete;
    Resumable(Resumable&& r) noexcept = default;
    Resumable& operator=(const Resumable& other) = delete;
    Resumable& operator=(Resumable&& other) noexcept = default;

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
     * Returns true if the function has completed orderly and provided a result.
     * If so, `get()` can be used to retrieve the result.
     */
    bool hasResult() const { return _done && _result.has_value(); }

    /**
     * Returns the function's result once it has completed. Must not be
     * called before completion; check with `hasResult()` first.
     */
    template<typename Result>
    const Result& get() const {
        assert(static_cast<bool>(_result));

        if constexpr ( std::is_same<Result, void>::value )
            return {};
        else {
            try {
                return std::any_cast<const Result&>(*_result);
            } catch ( const std::bad_any_cast& ) {
                throw InvalidArgument("mismatch in result type");
            }
        }
    }

    /** Returns true if the function has completed. **/
    explicit operator bool() const { return _done; }

private:
    void yielded();

    void checkFiber(const char* location) const {
        if ( ! _fiber )
            throw std::logic_error(std::string("fiber not set in ") + location);
    }

    std::unique_ptr<detail::Fiber> _fiber;
    bool _done = false;
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
