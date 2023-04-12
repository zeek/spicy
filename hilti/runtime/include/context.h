// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cassert>
#include <iostream>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <hilti/rt/fiber.h>
#include <hilti/rt/threading.h>

namespace hilti::rt {

/**
 * Thread execution context. One of these exists per virtual thread, plus one
 * for the main thread.
 *
 * The type's fields are considered implementation details and shouldn't be
 * accessed or modified by external code.
 */
struct Context {
    /**
     * @param vid virtual thread ID of the thread that will use the context
     */
    explicit Context(vthread::ID vid);
    ~Context();

    Context() = delete;
    Context(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(const Context&) = delete;
    Context& operator=(Context&&) = delete;

    /**
     * The ID of the virtual thread this context belongs to. `vthread::Main`
     * for the main thread.
     */
    vthread::ID vid;

    /**
     * Current resumable if we're inside a fiber so that yielding is
     * supported. Ownership remains with original caller.
     */
    resumable::Handle* resumable = nullptr;

    /**  Context-specific state for fiber management. */
    detail::FiberContext fiber;

    /**
     * Pointer to an array of (per thread) global variables allocated by the
     * linker code. Each array entry corresponds to the globals of one HILTI
     * module.
     */
    std::vector<std::shared_ptr<void>> hilti_globals;

    /** A user-defined cookie value that's carried around with the context. */
    void* cookie = nullptr;

    /** Current indent level for debug messages. */
    uint64_t debug_indent{};
};

namespace context {
namespace detail {

/**
 * Helper returning a reference to a thread-local variable storing the
 * current context. We can't access the pointer directly as that leads to
 * trouble with JITted code not resolving it correctly.
 *
 * Normally, this function should not be used; use `get()`/`set()` instead.
 */
extern Context*& current();

/** Returns the context for the main thread. */
extern Context* master();

/** Returns the context set for the current hardware thread. */
inline auto get(bool allow_missing_context = false) {
    auto* ctx = current();

    if ( ! allow_missing_context )
        assert(ctx);

    return ctx;
}

/**
 * Sets the current context. This will be visible to code inside the current
 * hardware thread.
 */
hilti::rt::Context* set(Context* ctx);

/**
 * Utility class that sets the current context's `resumable` field during its life-time.
 */
class ResumableSetter {
public:
    explicit ResumableSetter(resumable::Handle* r) {
        old = get()->resumable;
        get()->resumable = r;
    }

    ~ResumableSetter() { get()->resumable = old; }

    ResumableSetter(const ResumableSetter&) = delete;
    ResumableSetter(ResumableSetter&&) = delete;
    ResumableSetter& operator=(const ResumableSetter&) = delete;
    ResumableSetter& operator=(ResumableSetter&&) = delete;

    resumable::Handle* old;
};

} // namespace detail

/** Stores a user-defined cookie in the current context. */
inline void saveCookie(void* cookie) { detail::get()->cookie = cookie; }

/** Returns the user-defined cookie currently set in the current context.  */
inline void* cookie() { return detail::get()->cookie; }

/** Clears the user-defined cookie in the current context. */
inline void clearCookie() { detail::get()->cookie = nullptr; }

/**
 * Utility class that sets the current context's `cookie` field during its life-time.
 */
class CookieSetter {
public:
    explicit CookieSetter(void* cookie) {
        _old = detail::get()->cookie;
        detail::get()->cookie = cookie;
    }

    ~CookieSetter() { detail::get()->cookie = _old; }

    CookieSetter() = delete;
    CookieSetter(const CookieSetter&) = delete;
    CookieSetter(CookieSetter&&) = delete;
    CookieSetter& operator=(const CookieSetter&) = delete;
    CookieSetter& operator=(CookieSetter&&) = delete;

private:
    void* _old;
};

/**
 * Executes a function inside the current context's fiber.
 *
 * @param f function to execute
 * @param params arguments to pass into function
 * @return resumable object to either retrieve result or resume if execution got postponed
 */
template<typename Function, typename... Params>
Resumable execute(Function f, Params&&... params) {
    auto cb = [&](resumable::Handle* r) {
        auto _ = detail::ResumableSetter(r);
        return f(std::forward<Params>(params)...);
    };

    Resumable r(std::move(cb));
    r.run();
    return r;
}

} // namespace context
} // namespace hilti::rt
