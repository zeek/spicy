// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#ifdef _FORTIFY_SOURCE
// Disable in this file, the longjmps can cause false positives.
#undef _FORTIFY_SOURCE
#endif

#include "hilti/rt/fiber.h"

#include <cassert>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/context.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

#ifdef HILTI_HAVE_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif

using namespace hilti::rt;
using namespace hilti::rt::detail;

bool is_running_on_fiber() {
    // Before the fiber is first resumed the thread-local coroutine pointer
    // `aco_gtls_co` is not set up. On subsequent calls it points to the
    // currently active coroutine.
    return aco_gtls_co && globalState()->main_co.get() != aco_gtls_co;
}

extern "C" {

void _Trampoline() {
    auto* fiber = reinterpret_cast<Fiber*>(aco_get_arg());
    assert(fiber);

    HILTI_RT_DEBUG("fibers", fmt("[%p] entering trampoline loop", fiber));
    fiber->_finishSwitchFiber("trampoline-init");

    // Via recycling a fiber can run an arbitrary number of user jobs. So
    // this trampoline is really a loop that yields after it has finished its
    // function, and expects a new run function once it's resumed.
    ++Fiber::_initialized;

    while ( true ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] new iteration of trampoline loop", fiber));

        assert(fiber->_state == Fiber::State::Running);

        try {
            fiber->_result = (*fiber->_function)(fiber);
        } catch ( ... ) {
            HILTI_RT_DEBUG("fibers", fmt("[%p] got exception, forwarding", fiber));
            fiber->_exception = std::current_exception();
        }

        fiber->_function = {};
        fiber->_state = Fiber::State::Idle;
        fiber->_startSwitchFiber("trampoline-loop");

        assert(is_running_on_fiber());
        aco_yield();

        fiber->_finishSwitchFiber("trampoline-loop");
    }

    HILTI_RT_DEBUG("fibers", fmt("[%p] finished trampoline loop", fiber));

    aco_exit();
}
}

// FIXME(bbannier): move to GlobalState.
std::vector<Fiber*> Fiber::co_stack;

void Fiber::schedule(Fiber* fiber) { co_stack.push_back(fiber); }

void Fiber::unschedule(Fiber* fiber) {
    if ( ! fiber ) {
        co_stack.clear();
        return;
    }

    // Unschedule all coroutines dependent on this fiber.
    if ( auto it = std::find(co_stack.begin(), co_stack.end(), fiber); it != co_stack.end() )
        co_stack.erase(it, co_stack.end());
}

Fiber::Fiber()
    : co(std::unique_ptr<aco_t, void (*)(aco_t*)>(aco_create(globalState()->main_co.get(),
                                                             globalState()->share_st.get(), 0, _Trampoline, this),
                                                  [](aco_t* co) { aco_destroy(co); })) {
    HILTI_RT_DEBUG("fibers", fmt("[%p] allocated new fiber", this));

    ++_total_fibers;
    ++_current_fibers;

    if ( _current_fibers > _max_fibers )
        _max_fibers = _current_fibers;
}

class AbortException : public std::exception {};

Fiber::~Fiber() {
    HILTI_RT_DEBUG("fibers", fmt("[%p] deleting fiber", this));

    unschedule(this);
    --_current_fibers;
}

void Fiber::run() {
    // Run all previously scheduled coroutines.
    if ( ! co_stack.empty() ) {
        auto* fiber = *co_stack.rbegin();
        co_stack.pop_back();
        fiber->run();
    }
    co_stack.shrink_to_fit();

    if ( ! is_running_on_fiber() ) {
        if ( _state != State::Aborting )
            _state = State::Running;

        _startSwitchFiber("run", co->save_stack.ptr, co->save_stack.sz);
        aco_resume(co.get());
        _finishSwitchFiber("run");
    }
    else {
        // Schedule this fiber to be run next.
        co_stack.push_back(this);
        yield();
    }
}

void Fiber::yield() {
    _state = State::Yielded;
    _startSwitchFiber("yield");

    assert(is_running_on_fiber());
    aco_yield();

    _finishSwitchFiber("yield");

    if ( _state == State::Aborting )
        throw AbortException();
}

void Fiber::resume() { return run(); }

void Fiber::abort() {
    HILTI_RT_DEBUG("fibers", fmt("[%p] aborting fiber", this));

    _state = State::Aborting;
    unschedule(this);

    return run();
}

std::unique_ptr<Fiber> Fiber::create() {
    if ( ! globalState()->fiber_cache.empty() ) {
        auto f = std::move(globalState()->fiber_cache.back());
        globalState()->fiber_cache.pop_back();
        HILTI_RT_DEBUG("fibers", fmt("[%p] reusing fiber from cache", f.get()));
        return f;
    }

    return std::make_unique<Fiber>();
}

void Fiber::destroy(std::unique_ptr<Fiber> f) {
    if ( f->_state == State::Yielded )
        f->abort();

    if ( globalState()->fiber_cache.size() < CacheSize ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] putting fiber back into cache", f.get()));
        globalState()->fiber_cache.push_back(std::move(f));
        return;
    }

    HILTI_RT_DEBUG("fibers", fmt("[%p] cache size exceeded, deleting finished fiber", f.get()));
}

void Fiber::primeCache() {
    std::vector<std::unique_ptr<Fiber>> fibers;
    fibers.reserve(CacheSize);

    for ( unsigned int i = 0; i < CacheSize; i++ )
        fibers.emplace_back(Fiber::create());

    while ( fibers.size() ) {
        Fiber::destroy(std::move(fibers.back()));
        fibers.pop_back();
    }
}

void Fiber::reset() {
    unschedule();
    globalState()->fiber_cache.clear();

    _total_fibers = 0;
    _current_fibers = 0;
    _max_fibers = 0;
    _initialized = 0;
}

void Fiber::_startSwitchFiber(const char* tag, const void* stack_bottom, size_t stack_size) {
#ifdef HILTI_HAVE_SANITIZER
    if ( ! stack_bottom ) {
        stack_bottom = _asan.prev_bottom;
        stack_size = _asan.prev_size;
    }

    HILTI_RT_DEBUG("fibers", fmt("[%p/%s/asan] start_switch_fiber %p/%p (fake_stack=%p)", this, tag, stack_bottom,
                                 stack_size, &_asan.fake_stack));
    __sanitizer_start_switch_fiber(&_asan.fake_stack, stack_bottom, stack_size);
#else
    HILTI_RT_DEBUG("fibers", fmt("[%p] start_switch_fiber in %s", this, tag));
#endif
}

void Fiber::_finishSwitchFiber(const char* tag) {
#ifdef HILTI_HAVE_SANITIZER
    __sanitizer_finish_switch_fiber(_asan.fake_stack, &_asan.prev_bottom, &_asan.prev_size);
    HILTI_RT_DEBUG("fibers", fmt("[%p/%s/asan] finish_switch_fiber %p/%p (fake_stack=%p)", this, tag, _asan.prev_bottom,
                                 _asan.prev_size, _asan.fake_stack));
#else
    HILTI_RT_DEBUG("fibers", fmt("[%p] finish_switch_fiber in %s", this, tag));
#endif
}

void Resumable::run() {
    checkFiber("run");

    auto old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->run();
    context::detail::get()->resumable = old;

    yielded();
}

void Resumable::resume() {
    checkFiber("resume");

    auto old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->resume();
    context::detail::get()->resumable = old;

    yielded();
}

void Resumable::abort() {
    if ( ! _fiber )
        return;

    auto old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->abort();
    context::detail::get()->resumable = old;

    _result.reset();
    _done = true;
}

void Resumable::yielded() {
    if ( auto e = _fiber->exception() ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] rethrowing exception after fiber yielded", _fiber.get()));

        _done = true;
        _result.reset(); // just make sure optional is unset.
        detail::Fiber::destroy(std::move(_fiber));
        _fiber = nullptr;
        std::rethrow_exception(e);
        return;
    }

    if ( _fiber->isDone() ) {
        _done = true;
        _result = _fiber->result(); // might be unset
        detail::Fiber::destroy(std::move(_fiber));
        _fiber = nullptr;
        return;
    }
}

void detail::yield() {
    auto r = context::detail::get()->resumable;

    if ( ! r )
        throw RuntimeError("'yield' in non-suspendable context");

    r->yield();
    context::detail::get()->resumable = r;
}

Fiber::Statistics Fiber::statistics() {
    Statistics stats{
        .total = _total_fibers,
        .current = _current_fibers,
        .cached = globalState()->fiber_cache.size(),
        .max = _max_fibers,
        .initialized = _initialized,
    };

    return stats;
}
