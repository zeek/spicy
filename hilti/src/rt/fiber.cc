// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#ifdef _FORTIFY_SOURCE
// Disable in this file, the longjmps can cause false positives.
#undef _FORTIFY_SOURCE
#endif

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/context.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

#ifdef HILTI_HAVE_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif

using namespace hilti::rt;
using namespace hilti::rt::detail;

const void* _main_thread_bottom = nullptr;
std::size_t _main_thread_size = 0;

extern "C" {

void _Trampoline(unsigned int y, unsigned int x) {
    // Magic from from libtask/task.c to turn the two words back into a pointer.
    unsigned long z; // NOLINT
    z = (x << 16U);
    z <<= 16U;
    z |= y;
    auto fiber = (Fiber*)z; // NOLINT

    HILTI_RT_DEBUG("fibers", fmt("[%p] entering trampoline loop", fiber));
    fiber->_finishSwitchFiber("trampoline-init");

    // Via recycling a fiber can run an arbitrary number of user jobs. So
    // this trampoline is really a loop that yields after it has finished its
    // function, and expects a new run function once it's resumed.
    ++Fiber::_initialized;

    while ( true ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] new iteration of trampoline loop", fiber));

        assert(fiber->_state == Fiber::State::Running);

        if ( ! _setjmp(fiber->_trampoline) ) {
            // In parent.
            try {
                fiber->_result = (*fiber->_function)(fiber);
            } catch ( ... ) {
                HILTI_RT_DEBUG("fibers", fmt("[%p] got exception, forwarding", fiber));
                fiber->_exception = std::current_exception();
            }

            fiber->_state = Fiber::State::Finished;
        }

        if ( ! _setjmp(fiber->_fiber) ) {
            fiber->_function = {};
            fiber->_state = Fiber::State::Idle;
            fiber->_startSwitchFiber("trampoline-loop");
            _longjmp(fiber->_parent, 1);
        }

        fiber->_finishSwitchFiber("trampoline-loop");
    }

    HILTI_RT_DEBUG("fibers", fmt("[%p] finished trampoline loop", fiber));
}

Fiber::Fiber() {
    HILTI_RT_DEBUG("fibers", fmt("[%p] allocated new fiber", this));

    if ( getcontext(&_uctx) < 0 )
        internalError("fiber: getcontext failed");

    _uctx.uc_link = nullptr;
    _uctx.uc_stack.ss_size = StackSize;
    _uctx.uc_stack.ss_sp = new char[StackSize];
    _uctx.uc_stack.ss_flags = 0;

    // Magic from from libtask/task.c to turn the pointer into two words.
    // TODO(robin): Probably not portable ...
    unsigned long z = (unsigned long)this; // NOLINT
    unsigned int y = z;
    z >>= 16U;
    unsigned int x = (z >> 16U);

    makecontext(&_uctx, (void (*)())_Trampoline, 2, y, x); // NOLINT (cppcoreguidelines-pro-type-cstyle-cast)

    ++_total_fibers;
    ++_current_fibers;

    if ( _current_fibers > _max_fibers )
        _max_fibers = _current_fibers;
}
}

class AbortException : public std::exception {};

Fiber::~Fiber() {
    HILTI_RT_DEBUG("fibers", fmt("[%p] deleting fiber", this));

    delete[] static_cast<char*>(_uctx.uc_stack.ss_sp);
    --_current_fibers;
}

void Fiber::run() {
    auto init = (_state == State::Init);

    if ( _state != State::Aborting )
        _state = State::Running;

    if ( ! _setjmp(_parent) ) {
        _startSwitchFiber("run", _uctx.uc_stack.ss_sp, _uctx.uc_stack.ss_size);

        if ( init )
            setcontext(&_uctx);
        else {
            _longjmp(_fiber, 1);
        }

        internalError("fiber: unreachable reached");
    }

    _finishSwitchFiber("run");

    switch ( _state ) {
        case State::Yielded:
        case State::Idle: return;

        default: internalError("fiber: unexpected case");
    }
}

void Fiber::yield() {
    assert(_state == State::Running);

    if ( ! _setjmp(_fiber) ) {
        _state = State::Yielded;
        _startSwitchFiber("yield");
        _longjmp(_parent, 1);
    }

    _finishSwitchFiber("yield");

    if ( _state == State::Aborting )
        throw AbortException();
}

void Fiber::resume() {
    assert(_state == State::Yielded);
    return run();
}

void Fiber::abort() {
    assert(_state == State::Yielded);
    _state = State::Aborting;
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

    _result = false;
}

void Resumable::yielded() {
    if ( auto e = _fiber->exception() ) {
        HILTI_RT_DEBUG("fibers", fmt("[%p] rethrowing exception after fiber yielded", _fiber.get()));

        _result = false; // just make sure optional is set.
        detail::Fiber::destroy(std::move(_fiber));
        _fiber = nullptr;
        std::rethrow_exception(e);
        return;
    }

    if ( auto&& r = _fiber->result() ) {
        _result = std::move(r);
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
