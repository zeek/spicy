// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <csetjmp>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <hilti/rt/any.h>
#include <hilti/rt/autogen/config.h>
#include <hilti/rt/configuration.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/util.h>

struct Fiber;

// Fiber entry point for execution of fiber payload.
extern "C" void __fiber_run_trampoline(void* args);

// Fiber entry point for stack switch trampoline.
extern "C" void __fiber_switch_trampoline(void* args);

namespace hilti::rt {

namespace detail {
class Fiber;
} // namespace detail

namespace resumable {
/** Abstract handle providing access to a currently active function running inside a fiber.  */
using Handle = detail::Fiber;
} // namespace resumable

namespace detail {

/** Helper recording global stack resource usage. */
extern void trackStack();

/** Context-wide state for managing all fibers associated with that context. */
struct FiberContext {
    FiberContext();
    ~FiberContext();

    /** (Pseudo-)fiber representing the main function. */
    std::unique_ptr<detail::Fiber> main;

    /** Fiber implementing the switch trampoline. */
    std::unique_ptr<detail::Fiber> switch_trampoline;

    /** Currently executing fiber .*/
    detail::Fiber* current = nullptr;

    /** Fiber holding the shared stack (the fiber itself isn't used, just its stack memory) */
    std::unique_ptr<::Fiber> shared_stack;

    /** Cache of previously used fibers available for reuse. */
    std::vector<std::unique_ptr<Fiber>> cache;
};

/**
 * Helper retaining a fiber's saved stack content.
 */
struct StackBuffer {
    /**
     * Constructor.
     *
     * @param fiber fiber of which to track its current stack region
     */
    StackBuffer(const ::Fiber* fiber) : _fiber(fiber) {}

    /** Destructor. */
    ~StackBuffer();

    /**
     * Returns the lower/upper addresses of the memory region that is currently
     * actively in use by the fiber's stack. This value is only well-defined if
     * the fiber is *not* currently executing.
     **/
    std::pair<char*, char*> activeRegion() const;

    /**
     * Returns the lower/upper addresses of the memory region that is allocated
     * for the fiber's stack.
     **/
    std::pair<char*, char*> allocatedRegion() const;

    /**
     * Returns the size of the memory region that is currently actively in use
     * by the fiber's stack. This value is only well-defined if the fiber is
     * *not* currently executing.
     **/
    size_t activeSize() const;

    /** Returns the size of the memory region that's allocated for the fiber's stack. */
    size_t allocatedSize() const { return static_cast<size_t>(allocatedRegion().second - allocatedRegion().first); }

    /** Returns an approximate size of stack space left for a currently executing fiber. */
    size_t liveRemainingSize() const;

    /** Copies the fiber's stack out into an internally allocated buffer. */
    void save();

    /**
     * Copies previously saved stack content back into its original location.
     * This does nothing if no content has been saved so far.
     **/
    void restore() const;

private:
    const ::Fiber* _fiber;
    void* _buffer = nullptr; // allocated memory holding swapped out stack content
    size_t _buffer_size = 0; // amount currently allocated for `_buffer`
};

// Render stack region for use in debug output.
inline std::ostream& operator<<(std::ostream& out, const StackBuffer& s) {
    out << fmt("%p-%p:%zu", s.activeRegion().first, s.activeRegion().second, s.activeSize());
    return out;
}

/** Helper class to store stackless callbacks to be executed on fibers.*/
class Callback {
public:
    template<typename F>
    Callback(F f)
        : _f(std::move(f)), _invoke([](const hilti::rt::any& f, resumable::Handle* h) -> hilti::rt::any {
              return hilti::rt::any_cast<F>(f)(h);
          }) {}

    Callback(const Callback&) = default;
    Callback(Callback&&) = default;

    Callback& operator=(const Callback&) = default;
    Callback& operator=(Callback&&) = default;

    hilti::rt::any operator()(resumable::Handle* h) const { return _invoke(_f, h); }

private:
    hilti::rt::any _f; //< Type-erased storage for the concrete callback.
    hilti::rt::any (*_invoke)(const hilti::rt::any& f, resumable::Handle* h); //< Invoke type-erased callback.
};

/**
 * A fiber implements a co-routine that can at any time yield control back to
 * its caller, to be resumed later. This is the internal class implementing the
 * main functionality. It's used by `Resumable`, which provides the external
 * interface.
 */
class Fiber {
public:
    /** Type of fiber. */
    enum class Type : int64_t {
        IndividualStack, /**< Fiver using a dedicated local stack (needs more memory, but switching is fast) */
        SharedStack,     /**< Fiber sharing a global stack (needs less memory, but switching costs extra) */

        Main,             /**< Pseudo-fiber for the top-level process; for internally use only */
        SwitchTrampoline, /**< Fiber representing a trampoline for stack switching; for internal use only */
    };

    Fiber(Type type);
    ~Fiber();

    Fiber(const Fiber&) = delete;
    Fiber(Fiber&&) = delete;
    Fiber& operator=(const Fiber&) = delete;
    Fiber& operator=(Fiber&&) = delete;

    void init(Callback f) {
        _result = {};
        _exception = nullptr;
        _function = std::move(f);
    }

    /** Returns the fiber's type. */
    auto type() { return _type; }

    /** Returns the fiber's stack buffer. */
    const auto& stackBuffer() const { return _stack_buffer; }

    void run();
    void yield();
    void resume();
    void abort();

    bool isMain() const { return _type == Type::Main; }

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

    std::string tag() const;

    static std::unique_ptr<Fiber> create();
    static void destroy(std::unique_ptr<Fiber> f);
    static void primeCache();
    static void reset();

    struct Statistics {
        uint64_t total;
        uint64_t current;
        uint64_t cached;
        uint64_t max;
        uint64_t max_stack_size;
        uint64_t initialized;
    };

    static Statistics statistics();

private:
    friend void ::__fiber_run_trampoline(void* argsp);
    friend void ::__fiber_switch_trampoline(void* argsp);
    friend void detail::trackStack();

    enum class State { Init, Running, Aborting, Yielded, Idle, Finished };

    void _yield(const char* tag);
    void _activate(const char* tag);

    /** Code to run just before we switch to a fiber. */
    static void _startSwitchFiber(const char* tag, detail::Fiber* to);

    /** Code to run just after we have switched to a fiber. */
    static void _finishSwitchFiber(const char* tag);

    /** Low-level switch from one fiber to another. */
    static void _executeSwitch(const char* tag, detail::Fiber* from, detail::Fiber* to);

    Type _type;
    State _state{State::Init};
    std::optional<Callback> _function;
    std::optional<hilti::rt::any> _result;
    std::exception_ptr _exception;

    /** The underlying 3rdparty implementation of this fiber. */
    std::unique_ptr<::Fiber> _fiber;

    /** The coroutine this fiber will yield to. */
    Fiber* _caller = nullptr;

    /** Buffer for the fiber's stack when swapped out. */
    StackBuffer _stack_buffer;

#ifdef HILTI_HAVE_ASAN
    /** Additional tracking state that ASAN needs. */
    struct {
        const void* stack = nullptr;
        size_t stack_size = 0;
        void* fake_stack = nullptr;
    } _asan;
#endif

    // TODO: Usage of these isn't thread-safe. Should become "atomic" and
    // move into global state.
    inline static uint64_t _total_fibers;
    inline static uint64_t _current_fibers;
    inline static uint64_t _cached_fibers;
    inline static uint64_t _max_fibers;
    inline static uint64_t _max_stack_size;
    inline static uint64_t _initialized; // number of trampolines run
};

std::ostream& operator<<(std::ostream& out, const Fiber& fiber);

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
     * Creates an instance initialized with a function to execute. The
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
                return hilti::rt::any_cast<const Result&>(*_result);
            } catch ( const hilti::rt::bad_any_cast& ) {
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
    std::optional<hilti::rt::any> _result;
};

namespace resumable::detail {

/** Helper to deep-copy `Resumable` arguments in preparation for moving them to the heap. */
template<typename T>
auto copyArg(T t) {
    // In general, we can't move references to the heap.
    static_assert(! std::is_reference<T>::value, "copyArg() does not accept references other than ValueReference<T>.");
    return t;
}

// Special case: We don't want to (nor need to) deep-copy value references.
// Their payload already resides on the heap, so reuse that.
template<typename T>
ValueReference<T> copyArg(const ValueReference<T>& t) {
    return ValueReference<T>(t.asSharedPtr());
}

// Special case: We don't want to (nor need to) deep-copy value references.
// Their payload already resides on the heap, so reuse that.
template<typename T>
ValueReference<T> copyArg(ValueReference<T>& t) {
    return ValueReference<T>(t.asSharedPtr());
}

} // namespace resumable::detail

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
