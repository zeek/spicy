#include <benchmark/benchmark.h>

#include <hilti/rt/fiber.h>
#include <hilti/rt/init.h>
#include <hilti/rt/result.h>

void SomeFunction() {}

static void init(benchmark::State& state) {
    for ( auto _ : state ) {
        state.PauseTiming();
        hilti::rt::done();
        state.ResumeTiming();

        hilti::rt::init();
    }
}

static void done(benchmark::State& state) {
    for ( auto _ : state ) {
        state.PauseTiming();
        hilti::rt::done();
        hilti::rt::init();
        state.ResumeTiming();

        hilti::rt::done();
    }
}

static void execute_one(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto r = hilti::rt::fiber::execute([&](hilti::rt::resumable::Handle* h) { return hilti::rt::Nothing(); });

        state.ResumeTiming();

        while ( ! r.hasResult() ) {
            r.resume();
        }
    }
}

static void execute_one_yield(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto r = hilti::rt::fiber::execute([](hilti::rt::resumable::Handle* h) {
            h->yield();
            return hilti::rt::Nothing();
        });

        state.ResumeTiming();

        while ( ! r.hasResult() ) {
            r.resume();
        }
    }
}

static void execute_yield_to_other(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto r1 = hilti::rt::fiber::execute([&](hilti::rt::resumable::Handle* h) {
            h->yield();
            return hilti::rt::Nothing();
        });

        auto r2 = hilti::rt::fiber::execute([&](hilti::rt::resumable::Handle* h) {
            r1.resume();
            return hilti::rt::Nothing();
        });

        state.ResumeTiming();

        while ( ! r2.hasResult() ) {
            r2.resume();
        }
    }
}

BENCHMARK(init);
BENCHMARK(done);
BENCHMARK(execute_one);
BENCHMARK(execute_one_yield);
BENCHMARK(execute_yield_to_other);

BENCHMARK_MAIN();
