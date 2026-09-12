// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cstdint>
#include <memory>

#include <hilti/rt/init.h>
#include <hilti/rt/types/reference.h>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
#include <benchmark/benchmark.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

namespace {

// Mirrors generated unit types which derive from `Controllable` so that
// `ValueReference::self()` can wrap `this` into a value reference.
struct Dummy : hilti::rt::Controllable<Dummy> {
    uint64_t x = 0;
};

} // namespace

static void valueref_construct_default(benchmark::State& state) {
    hilti::rt::init();

    // NOLINTNEXTLINE
    for ( auto _ : state )
        benchmark::DoNotOptimize(hilti::rt::ValueReference<Dummy>());
}

static void valueref_construct_value(benchmark::State& state) {
    hilti::rt::init();

    // NOLINTNEXTLINE
    for ( auto _ : state ) {
        Dummy d;
        d.x = 42;
        benchmark::DoNotOptimize(hilti::rt::ValueReference<Dummy>(std::move(d)));
    }
}

static void valueref_copy(benchmark::State& state) {
    hilti::rt::init();

    auto ref = hilti::rt::ValueReference<Dummy>();

    // NOLINTNEXTLINE
    for ( auto _ : state )
        benchmark::DoNotOptimize(hilti::rt::ValueReference<Dummy>(ref));
}

static void valueref_move(benchmark::State& state) {
    hilti::rt::init();

    // NOLINTNEXTLINE
    for ( auto _ : state ) {
        auto ref = hilti::rt::ValueReference<Dummy>();
        benchmark::DoNotOptimize(hilti::rt::ValueReference<Dummy>(std::move(ref)));
    }
}

static void valueref_deref(benchmark::State& state) {
    hilti::rt::init();

    auto ref = hilti::rt::ValueReference<Dummy>();

    // NOLINTNEXTLINE
    for ( auto _ : state )
        benchmark::DoNotOptimize((*ref).x);
}

static void valueref_self(benchmark::State& state) {
    hilti::rt::init();

    auto owned = std::make_shared<Dummy>();

    // NOLINTNEXTLINE
    for ( auto _ : state )
        benchmark::DoNotOptimize(hilti::rt::ValueReference<Dummy>::self(owned.get()));
}

static void valueref_self_then_deref(benchmark::State& state) {
    hilti::rt::init();

    auto owned = std::make_shared<Dummy>();

    // NOLINTNEXTLINE
    for ( auto _ : state ) {
        auto ref = hilti::rt::ValueReference<Dummy>::self(owned.get());
        benchmark::DoNotOptimize((*ref).x);
    }
}

static void valueref_as_shared_ptr(benchmark::State& state) {
    hilti::rt::init();

    auto ref = hilti::rt::ValueReference<Dummy>();

    // NOLINTNEXTLINE
    for ( auto _ : state )
        benchmark::DoNotOptimize(ref.asSharedPtr());
}

BENCHMARK(valueref_construct_default);
BENCHMARK(valueref_construct_value);
BENCHMARK(valueref_copy);
BENCHMARK(valueref_move);
BENCHMARK(valueref_deref);
BENCHMARK(valueref_self);
BENCHMARK(valueref_self_then_deref);
BENCHMARK(valueref_as_shared_ptr);
