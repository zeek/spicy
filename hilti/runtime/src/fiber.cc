// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <fiber/fiber.h>

#include <memory>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/configuration.h>
#include <hilti/rt/context.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/util.h>

#ifdef HILTI_HAVE_ASAN
#include <sanitizer/asan_interface.h>
#include <sanitizer/common_interface_defs.h>
#endif

using namespace hilti::rt;

#ifndef HILTI_HAVE_ASAN
// Defaults for normal operation.
static const auto DefaultFiberType = detail::Fiber::Type::SharedStack; // share stack by default
static const auto AlwaysUseStackSwitchTrampoline = false;              // use switch trampoline only with shared stacks
static const auto FiberGuardFlags = FIBER_FLAG_GUARD_LO | FIBER_FLAG_GUARD_HI;

#define ASAN_NO_OPTIMIZE // just leave empty

#else
// Because the stack copying triggers false positives with ASAN, we use
// individual stacks when that's active. We still force use of the stack
// switcher trampoline in that case, so that we get that piece at least.
//
// TODO: If we could whitelist the memcpys, that would solve the problem, but I
// haven't been able to do that using any of the sanitizer attributes; they
// just seem to be ignored.
static const auto DefaultFiberType = detail::Fiber::Type::IndividualStack;
static const auto AlwaysUseStackSwitchTrampoline = true;
static const auto FiberGuardFlags = 0; // leak sanitizer may abort with "Tracer caught signal 11" if pages get protected

#if defined(__clang__)
#define ASAN_NO_OPTIMIZE __attribute__((optnone))
#elif defined(__GNUC__)
#define ASAN_NO_OPTIMIZE __attribute__((optimize(0)))
#endif

#endif

// Pre-allocate this so that we don't need to create a std::string on the fly
// when HILTI_RT_FIBER_DEBUG executes. That avoids a false positive with
// ASAN during fiber switching when using GCC/libc++.
static const std::string debug_stream_fibers = "fibers";

// Wrapper similar to HILTI_RT_DEBUG that adds the current fiber to the message.
#define HILTI_RT_FIBER_DEBUG(tag, msg)                                                                                 \
    {                                                                                                                  \
        if ( ::hilti::rt::detail::unsafeGlobalState()->debug_logger &&                                                 \
             ::hilti::rt::detail::unsafeGlobalState()->debug_logger->isEnabled(debug_stream_fibers) )                  \
            ::hilti::rt::debug::detail::print(debug_stream_fibers,                                                     \
                                              fmt("[%s/%s] %s", *context::detail::get()->fiber.current, tag, msg));    \
    }

#define HILTI_RT_FIBER_DEBUG_NO_CONTEXT(tag, msg)                                                                      \
    {                                                                                                                  \
        if ( ::hilti::rt::detail::unsafeGlobalState()->debug_logger &&                                                 \
             ::hilti::rt::detail::unsafeGlobalState()->debug_logger->isEnabled(debug_stream_fibers) )                  \
            ::hilti::rt::debug::detail::print(debug_stream_fibers, fmt("[none/%s] %s", tag, msg));                     \
    }

extern "C" {

// A dummy fallback function which will be put on the bottom of all fibers'
// call stacks. This function should never execute.
[[noreturn]] static void fiber_bottom_abort(Fiber* fiber, void* args) { abort(); }

// Fiber entry point for execution of payload functions.
void __fiber_run_trampoline(void* argsp) {
    auto* fiber = context::detail::get()->fiber.current;
    hilti::rt::detail::Fiber::_finishSwitchFiber("trampoline-run");

    // We recycle fibers to run an arbitrary number of user jobs. So this
    // trampoline is actually a loop that yields after it has finished its
    // function, and expects a new run function once it's resumed.
    ++detail::Fiber::_initialized;

    HILTI_RT_FIBER_DEBUG("trampoline-run", "entering trampoline loop");

    while ( true ) {
        HILTI_RT_FIBER_DEBUG("trampoline-run", "new iteration of trampoline loop");
        assert(fiber->_caller);
        assert(fiber->_state == detail::Fiber::State::Running);

        try {
            fiber->_result = (*fiber->_function)(fiber);
            HILTI_RT_FIBER_DEBUG("trampoline-run", "payload function finished");
        } catch ( ... ) {
            HILTI_RT_FIBER_DEBUG("trampoline-run", "got exception, forwarding");
            fiber->_exception = std::current_exception();
        }

        fiber->_function = {};
        fiber->_state = detail::Fiber::State::Idle;
        fiber->_yield("trampoline-run");
    }

    HILTI_RT_FIBER_DEBUG("trampoline-run", "finished trampoline loop");
}

// Captures arguments passed into stack switcher trampoline.
struct SwitchArgs {
    detail::Fiber* switcher = nullptr;
    detail::Fiber* from = nullptr;
    detail::Fiber* to = nullptr;
};

// Fiber entry point for stack switcher trampoline.
//
// This function will never run to completion; do not store anything on its
// stack that would need cleanup.
void __fiber_switch_trampoline(void* argsp) {
    auto* args = reinterpret_cast<SwitchArgs*>(argsp);
    detail::Fiber::_finishSwitchFiber("stack-switcher");

    auto* from = args->from;
    auto* to = args->to;
    // Explicitly put the log message on the stack to work around ASAN false positives on macos.
    if ( detail::unsafeGlobalState()->debug_logger &&
         detail::unsafeGlobalState()->debug_logger->isEnabled(debug_stream_fibers) ) {
        const auto msg = fmt("switching from %s to %s", from, to);
        HILTI_RT_FIBER_DEBUG("stack-switcher", msg);
    }

    if ( from->_type == detail::Fiber::Type::SharedStack )
        from->_stack_buffer.save();

    if ( to->_type == detail::Fiber::Type::SharedStack )
        to->_stack_buffer.restore();

    detail::Fiber::_executeSwitch("stack-switcher", args->switcher, to);

    // We won't return here.
    cannot_be_reached();
}
}

detail::FiberContext::FiberContext() {
    main = std::make_unique<detail::Fiber>(detail::Fiber::Type::Main);
    current = main.get();
    switch_trampoline = std::make_unique<detail::Fiber>(detail::Fiber::Type::SwitchTrampoline);

    // Instantiate an unused fiber just to create the shared stack.
    shared_stack = std::make_unique<::Fiber>();
    if ( ! ::fiber_alloc(shared_stack.get(), configuration::get().fiber_shared_stack_size, fiber_bottom_abort, this,
                         FiberGuardFlags) )
        throw RuntimeError("could not allocate shared stack");
}

detail::FiberContext::~FiberContext() { ::fiber_destroy(shared_stack.get()); }

detail::Fiber::Fiber(Type type) : _type(type), _fiber(std::make_unique<::Fiber>()), _stack_buffer(_fiber.get()) {
#ifndef NDEBUG
    // We won't have a context yet when the main/stack-switcher fibers are
    // created.
    if ( type != Type::Main && type != Type::SwitchTrampoline ) {
        HILTI_RT_FIBER_DEBUG("ctor", fmt("allocated new fiber %s", *this));
    }
    else {
        HILTI_RT_FIBER_DEBUG_NO_CONTEXT("ctor", fmt("allocated new fiber %s", *this));
    }
#endif

    switch ( type ) {
        case Type::Main: {
            ::fiber_init_toplevel(_fiber.get());

            // We assume/require that the main stack is at least at large as
            // our shared fiber stack. With that, we can compute a stack
            // starting address that's safely inside the actual stack. That
            // address can then be used for stack size checking in checkStack()
            // to catch recursions going too deep while we're running inside
            // the main fiber.
            const auto min_size = configuration::get().fiber_shared_stack_size;

            rlimit limit;
            if ( ::getrlimit(RLIMIT_STACK, &limit) < 0 )
                throw RuntimeError("could not get current stack size");

            if ( limit.rlim_cur < min_size )
                throw RuntimeError(fmt("process stack size too small, need at least %zu KB", min_size / 1024));

#if __x86_64__ || __arm__ || __arm64__ || __aarch64__ || __i386__
            // There's a bit of fuzziness here as the current frame won't start
            // exactly at the beginning of the stack---but should be good
            // enough.
            _fiber->stack = reinterpret_cast<char*>(__builtin_frame_address(0)) - min_size;
            _fiber->stack_size = min_size;
#else
#error "unsupported architecture in hilti::rt::detail::Fiber::Fiber()"
#endif

            // ASAN stack size will be set dynamically later.
            break;
        }

        case Type::SwitchTrampoline:
            if ( ! ::fiber_alloc(_fiber.get(), configuration::detail::unsafeGet().fiber_individual_stack_size,
                                 fiber_bottom_abort, this, FiberGuardFlags) )
                internalError("could not allocate individual-stack fiber");

#ifdef HILTI_HAVE_ASAN
            _asan.stack = ::fiber_stack(_fiber.get());
            _asan.stack_size = configuration::get().fiber_individual_stack_size;
#endif
            break;

        case Type::SharedStack: {
            auto* shared_stack = context::detail::get()->fiber.shared_stack.get();
            ::fiber_init(_fiber.get(), shared_stack->stack, shared_stack->stack_size, fiber_bottom_abort, this);

#ifdef HILTI_HAVE_ASAN
            _asan.stack = ::fiber_stack(_fiber.get());
            _asan.stack_size = configuration::get().fiber_shared_stack_size;
#endif
            break;
        }

        case Type::IndividualStack: {
            if ( ! ::fiber_alloc(_fiber.get(), configuration::detail::unsafeGet().fiber_individual_stack_size,
                                 fiber_bottom_abort, this, FiberGuardFlags) )
                internalError("could not allocate individual-stack fiber");

#ifdef HILTI_HAVE_ASAN
            _asan.stack = ::fiber_stack(_fiber.get());
            _asan.stack_size = configuration::get().fiber_individual_stack_size;
#endif
            break;
        }
    }

    switch ( type ) {
        case Type::SharedStack:
        case Type::IndividualStack: {
            // We do bookkeeping only for the "real" fibers with payload.
            ++_total_fibers;
            ++_current_fibers;

            // NOLINTNEXTLINE(readability-use-std-min-max)
            if ( _current_fibers > _max_fibers )
                _max_fibers = _current_fibers;
        }

        case Type::SwitchTrampoline:
        case Type::Main:
            // Nothing to do for these.
            break;
    };
}

// Exception raised by a fiber resuming operation in case it has been aborted
// in the meantime. This must not be derived from `std::exception` to guarantee
// that it will bubble back up to the fiber code, without being caught by any
// intermediary catch handlers.
struct AbortException {};

detail::Fiber::~Fiber() {
#ifndef NDEBUG
    // We won't have a context anymore when the main/stack-switcher fibers are
    // destroyed.
    if ( _type != Type::Main && _type != Type::SwitchTrampoline ) {
        HILTI_RT_FIBER_DEBUG("dtor", fmt("deleting fiber %s", *this));
    }
    else {
        HILTI_RT_FIBER_DEBUG_NO_CONTEXT("dtor", fmt("deleting fiber %s", *this));
    }
#endif

    if ( _type == Type::Main )
        return;

    ::fiber_destroy(_fiber.get());

    if ( _type != Type::SwitchTrampoline )
        --_current_fibers;
}

detail::StackBuffer::~StackBuffer() { free(_buffer); }

std::pair<char*, char*> detail::StackBuffer::activeRegion() const {
    // The direction in which the stack grows is platform-specific. It's
    // probably gong to be growing downwards pretty much everywhere, but to be
    // safe we whitelist platforms that we have confirmed to do so.
#if __x86_64__ || __arm__ || __arm64__ || __aarch64__ || __i386__
    auto* lower = reinterpret_cast<char*>(_fiber->regs.sp);
    auto* upper = reinterpret_cast<char*>(_fiber->regs.sp) + fiber_stack_used_size(_fiber);
#else
#error "unsupported architecture in hilti::rt::detail::StackBuffer::activeRegion"
#endif

    return std::make_pair(lower, upper);
}

std::pair<char*, char*> detail::StackBuffer::allocatedRegion() const {
    auto* lower = reinterpret_cast<char*>(::fiber_stack(_fiber));
    return std::make_pair(lower, lower + ::fiber_stack_size(_fiber));
}

size_t detail::StackBuffer::liveRemainingSize() const {
    assert(::fiber_is_executing(_fiber)); // must be live

    // Whitelist architectures where we know how to do this.
#if __x86_64__ || __arm__ || __arm64__ || __aarch64__ || __i386__
    // See
    // https://stackoverflow.com/questions/20059673/print-out-value-of-stack-pointer
    // for discussion of how to get stack pointer.
    auto* sp = reinterpret_cast<char*>(__builtin_frame_address(0));
    auto* lower = reinterpret_cast<char*>(::fiber_stack(_fiber));

    // Double-check we're pointing into the right space (ignore for the main
    // fiber as our upper bound might not be quite right, and hence the current
    // SP might be passed it.)
    assert((sp >= allocatedRegion().first && sp < allocatedRegion().second) || ::fiber_is_toplevel(_fiber));

    return static_cast<size_t>(sp - lower);
#else
#error "unsupported architecture in hilti::rt::detail::StackBuffer::liveRemainingSize()"
#endif
}

size_t detail::StackBuffer::activeSize() const { return ::fiber_stack_used_size(_fiber); }

void detail::StackBuffer::save() {
    auto want_buffer_size = std::max(activeSize(), configuration::get().fiber_shared_stack_swap_size_min);

    // Round to KB boundary to avoid frequent reallocations.
    want_buffer_size = ((want_buffer_size >> 10) + 1) << 10;

    if ( want_buffer_size != _buffer_size ) {
        HILTI_RT_FIBER_DEBUG("stack-switcher", fmt("%sallocating %zu bytes of swap space for stack %s",
                                                   (_buffer ? "re" : ""), want_buffer_size, *this));

        if ( _buffer )
            free(_buffer);

        _buffer = ::malloc(want_buffer_size);
        if ( ! _buffer )
            throw RuntimeError("out of memory when saving fiber stack");

        _buffer_size = want_buffer_size;
    }

    HILTI_RT_FIBER_DEBUG("stack-switcher", fmt("saving stack %s to %p", *this, _buffer));
    auto [lower, upper] = activeRegion();
    assert(lower <= upper);
    size_t len = upper - lower;
    assert(_buffer_size >= len);
    ::memcpy(_buffer, lower, len);
}

void detail::StackBuffer::restore() const {
    if ( ! _buffer )
        return;

    HILTI_RT_FIBER_DEBUG("stack-switcher", fmt("restoring stack %s from %p", *this, _buffer));

    auto [lower, upper] = activeRegion();
    ::memcpy(lower, _buffer, (upper - lower));
}

// ASAN doesn't seem to always track the new stack correctly if this method gets optimized.
void ASAN_NO_OPTIMIZE detail::Fiber::_startSwitchFiber(const char* tag, detail::Fiber* to) {
#ifdef HILTI_HAVE_ASAN
    auto* current = context::detail::get()->fiber.current;
    __sanitizer_start_switch_fiber(&current->_asan.fake_stack, to->_asan.stack, to->_asan.stack_size);

    assert(to->_asan.stack);
    HILTI_RT_FIBER_DEBUG(tag, fmt("asan-start: new-stack=%p:%zu fake-stack=%p", to->_asan.stack, to->_asan.stack_size,
                                  current->_asan.fake_stack));
#endif
}

// ASAN doesn't seem to always track the new stack correctly if this method gets optimized.
void ASAN_NO_OPTIMIZE detail::Fiber::_finishSwitchFiber(const char* tag) {
#ifdef HILTI_HAVE_ASAN
    auto* context = context::detail::get();
    auto* current = context->fiber.current;

    const void* prev_bottom = nullptr;
    size_t prev_size = 0;
    __sanitizer_finish_switch_fiber(current->_asan.fake_stack, &prev_bottom, &prev_size);

    // Explicitly put the log message on the stack to work around ASAN false positives on macos.
    if ( detail::unsafeGlobalState()->debug_logger &&
         detail::unsafeGlobalState()->debug_logger->isEnabled(debug_stream_fibers) ) {
        const auto msg =
            fmt("asan-finish: prev-stack=%s/%zu fake-stack=%p", prev_bottom, prev_size, current->_asan.fake_stack);
        HILTI_RT_FIBER_DEBUG(tag, msg);
    }

    // By construction, the very first time this method is called, we must just
    // have finished switching over from the main fiber. Record its stack.
    if ( ! context->fiber.main->_asan.stack ) {
        context->fiber.main->_asan.stack = prev_bottom;
        context->fiber.main->_asan.stack_size = prev_size;
    }
#endif
}

void ASAN_NO_OPTIMIZE detail::Fiber::_executeSwitch(const char* tag, detail::Fiber* from, detail::Fiber* to) {
    HILTI_RT_FIBER_DEBUG(tag, fmt("executing fiber switch from %s to %s", *from, *to));

    detail::Fiber::_startSwitchFiber(tag, to);
    context::detail::get()->fiber.current = to;
    ::fiber_switch(from->_fiber.get(), to->_fiber.get());
    detail::Fiber::_finishSwitchFiber(tag);

    HILTI_RT_FIBER_DEBUG(tag, fmt("resuming after fiber switch returns back to %s", *from));
}

void detail::Fiber::_activate(const char* tag) {
    auto* context = context::detail::get();
    auto* current = context->fiber.current;
    assert(current && current != this);
    assert(current->_type != Type::SwitchTrampoline);

    HILTI_RT_FIBER_DEBUG(tag, fmt("activating fiber %s (stack %p)", *this, ::fiber_stack(_fiber.get())));

    _caller = current;

    if ( current->_type == Type::SharedStack || _type == Type::SharedStack || AlwaysUseStackSwitchTrampoline ) {
        // Need to go through switch trampoline.
        auto* stack_switcher = context->fiber.switch_trampoline.get();

        SwitchArgs args;
        args.switcher = stack_switcher;
        args.from = current;
        args.to = this;

        // Reinitialize fiber with same stack.
        auto* fiber = stack_switcher->_fiber.get();
#ifdef HILTI_HAVE_ASAN
        // Memory may still have guard regions from previous usage.
        __asan_unpoison_memory_region(fiber->alloc_stack, ::fiber_stack_size(fiber));
#endif
        auto* saved_alloc_stack = fiber->alloc_stack; // fiber_init() resets this
        ::fiber_init(fiber, ::fiber_stack(fiber), ::fiber_stack_size(fiber), fiber_bottom_abort, this);
        ::fiber_push_return(fiber, __fiber_switch_trampoline, &args, sizeof(args));
        fiber->alloc_stack = saved_alloc_stack;
        fiber->state |= FiberGuardFlags; // fiber_init() clears these
        _executeSwitch(tag, current, stack_switcher);
    }
    else
        // Can jump directly.
        _executeSwitch(tag, current, this);
}

void detail::Fiber::_yield(const char* tag) {
    auto* context = context::detail::get();

#ifndef NDEBUG
    auto* current = context->fiber.current;
    assert(_caller);
    assert(current && current == this);
    assert(current != _caller);
    assert(current->_type != Type::SwitchTrampoline);
#endif

    HILTI_RT_FIBER_DEBUG(tag, fmt("yielding to caller %s", _caller));

    if ( _type == Type::SharedStack || _caller->_type == Type::SharedStack || AlwaysUseStackSwitchTrampoline ) {
        // Need to go through switch trampoline.
        auto* stack_switcher = context->fiber.switch_trampoline.get();

        SwitchArgs args;
        args.switcher = stack_switcher;
        args.from = this;
        args.to = _caller;

        // Reinitialize fiber with same stack.
        auto* fiber = stack_switcher->_fiber.get();
#ifdef HILTI_HAVE_ASAN
        // Memory may still have guard regions from previous usage.
        __asan_unpoison_memory_region(fiber->alloc_stack, ::fiber_stack_size(fiber));
#endif
        auto* saved_alloc_stack = fiber->alloc_stack; // fiber_init() resets this
        ::fiber_init(fiber, ::fiber_stack(fiber), ::fiber_stack_size(fiber), fiber_bottom_abort, this);
        ::fiber_push_return(fiber, __fiber_switch_trampoline, &args, sizeof(args));
        fiber->alloc_stack = saved_alloc_stack;
        fiber->state |= FiberGuardFlags; // fiber_init() clears these
        _executeSwitch(tag, this, stack_switcher);
    }
    else
        // Can jump directly.
        _executeSwitch(tag, this, _caller);
}

std::string detail::Fiber::tag() const {
    switch ( _type ) {
        case Type::Main: return "main";
        case Type::SwitchTrampoline: return "switcher";
        case Type::SharedStack: return "shared-stack";
        case Type::IndividualStack: return "owned-stack";
    }

    cannot_be_reached();
}

namespace hilti::rt::detail {
std::ostream& operator<<(std::ostream& out, const detail::Fiber& fiber) {
    out << fmt("%s-%p", fiber.tag(), &fiber);
    return out;
}
} // namespace hilti::rt::detail

void detail::Fiber::run() {
    auto init = (_state == State::Init);

    if ( _state != State::Aborting )
        _state = State::Running;

    if ( init ) {
        // TODO: It would seem reasonable to move into this the constructor
        // where we initialize the fiber. However, that leads to crashes; not
        // sure why?
        void* dummy_args; // not used, but need a non-null pointer
        ::fiber_reserve_return(_fiber.get(), __fiber_run_trampoline, &dummy_args, 0);
    }

    _activate("run");

    switch ( _state ) {
        case State::Yielded:
        case State::Idle: return;
        default: internalError(fmt("fiber: unexpected state (%d)", static_cast<int>(_state)));
    }
}

void detail::Fiber::yield() {
    assert(_state == State::Running);

    _state = State::Yielded;
    _yield("yield");

    if ( _state == State::Aborting )
        throw AbortException();
}

void detail::Fiber::resume() {
    assert(_state == State::Yielded);
    run();
}

void detail::Fiber::abort() {
    assert(_state == State::Yielded);
    _state = State::Aborting;

    if ( ! context::detail::get(true) )
        return;

    try {
        run();
    } catch ( const AbortException& ) {
        // Exception is expected here when the fiber realizes it has been
        // aborted.
    }
}

std::unique_ptr<detail::Fiber> detail::Fiber::create() {
    auto* context = context::detail::get();
    auto& cache = context->fiber.cache;
    if ( ! cache.empty() ) {
        auto f = std::move(cache.back());
        cache.pop_back();
        --_cached_fibers;
        HILTI_RT_FIBER_DEBUG("create", fmt("reusing fiber %s from cache", *f.get()));
        return f;
    }

    return std::make_unique<Fiber>(DefaultFiberType);
}

void detail::Fiber::destroy(std::unique_ptr<detail::Fiber> f) {
    if ( f->isMain() )
        return;

    if ( f->_state == State::Yielded )
        f->abort();

    auto* context = context::detail::get(true);

    if ( ! context )
        return;

    auto& cache = context->fiber.cache;
    if ( cache.size() < configuration::detail::unsafeGet().fiber_cache_size ) {
        HILTI_RT_FIBER_DEBUG("destroy", fmt("putting fiber %s back into cache", *f.get()));
        cache.push_back(std::move(f));
        ++_cached_fibers;
        return;
    }

    HILTI_RT_FIBER_DEBUG("destroy", fmt("cache size exceeded, deleting finished fiber %s", *f.get()));
}

void detail::Fiber::primeCache() {
    std::vector<std::unique_ptr<Fiber>> fibers;
    fibers.reserve(configuration::get().fiber_cache_size);

    for ( unsigned int i = 0; i < configuration::get().fiber_cache_size; i++ )
        fibers.emplace_back(Fiber::create());

    while ( fibers.size() ) {
        Fiber::destroy(std::move(fibers.back()));
        fibers.pop_back();
    }
}

void detail::Fiber::reset() {
    context::detail::get()->fiber.cache.clear();
    _total_fibers = 0;
    _current_fibers = 0;
    _cached_fibers = 0;
    _max_fibers = 0;
    _max_stack_size = 0;
    _initialized = 0;
}

void Resumable::run() {
    checkFiber("run");

    auto* old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->run();
    context::detail::get()->resumable = old;

    yielded();
}

void Resumable::resume() {
    checkFiber("resume");

    auto* old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->resume();
    context::detail::get()->resumable = old;

    yielded();
}

void Resumable::abort() {
    if ( ! _fiber )
        return;

    auto* old = context::detail::get()->resumable;
    context::detail::get()->resumable = handle();
    _fiber->abort();
    context::detail::get()->resumable = old;

    _result.reset();
    _done = true;
}

void Resumable::yielded() {
    if ( auto e = _fiber->exception() ) {
        HILTI_RT_FIBER_DEBUG("yielded", fmt("rethrowing exception after fiber %s yielded", *_fiber.get()));

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
    auto* r = context::detail::get()->resumable;

    if ( ! r )
        throw RuntimeError("'yield' in non-suspendable context");

    r->yield();
    context::detail::get()->resumable = r;
}

void detail::trackStack() {
    auto* fiber = context::detail::get()->fiber.current;

    if ( fiber->type() == Fiber::Type::Main )
        return;

    if ( fiber->type() == Fiber::Type::IndividualStack || fiber->type() == Fiber::Type::SharedStack ) {
        // NOLINTNEXTLINE(readability-use-std-min-max)
        if ( auto size = fiber->stackBuffer().activeSize(); size > detail::Fiber::_max_stack_size )
            detail::Fiber::_max_stack_size = size;
    }
}

detail::Fiber::Statistics detail::Fiber::statistics() {
    Statistics stats{
        .total = _total_fibers,
        .current = _current_fibers,
        .cached = _cached_fibers,
        .max = _max_fibers,
        .max_stack_size = _max_stack_size,
        .initialized = _initialized,
    };

    return stats;
}
