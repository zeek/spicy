#include <alloca.h>
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
        auto stack = state.range(0);

        state.PauseTiming();

        auto r = hilti::rt::Resumable([&](hilti::rt::resumable::Handle* h) {
            auto* xs = reinterpret_cast<int**>(alloca(stack * sizeof(char)));
            benchmark::DoNotOptimize(xs[stack - 1]);
            return hilti::rt::Nothing();
        });

        state.ResumeTiming();
        r.resume();
    }
}

static void execute_one_yield(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto stack = state.range(0);

        auto r = hilti::rt::Resumable([stack](hilti::rt::resumable::Handle* h) {
            auto* xs = reinterpret_cast<int**>(alloca(stack * sizeof(char)));
            benchmark::DoNotOptimize(xs[stack - 1]);
            h->yield();
            benchmark::DoNotOptimize(xs[stack - 1]);
            return hilti::rt::Nothing();
        });

        while ( ! r.hasResult() ) {
            state.ResumeTiming();
            r.resume();
            state.PauseTiming();
        }
    }
}

static void execute_yield_to_other(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto stack = state.range(0);

        auto r1 = hilti::rt::Resumable([stack](hilti::rt::resumable::Handle* h) {
            auto* xs = reinterpret_cast<int**>(alloca(stack * sizeof(char)));
            benchmark::DoNotOptimize(xs[stack - 1]);
            h->yield();
            benchmark::DoNotOptimize(xs[stack - 1]);
            return hilti::rt::Nothing();
        });

        auto r2 = hilti::rt::Resumable([stack, &r1](hilti::rt::resumable::Handle* h) {
            auto* xs = reinterpret_cast<int**>(alloca(stack * sizeof(char)));
            benchmark::DoNotOptimize(xs[stack - 1]);
            r1.resume();
            benchmark::DoNotOptimize(xs[stack - 1]);
            return hilti::rt::Nothing();
        });

        while ( ! r2.hasResult() ) {
            state.ResumeTiming();
            r2.resume();
            state.PauseTiming();
        }
    }
}

static void execute_many(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto stack = state.range(0);
        auto fibers = state.range(1);

        std::vector<hilti::rt::Resumable> rs;

        for ( int i = 0; i < fibers; ++i ) {
            rs.push_back(hilti::rt::Resumable([&](hilti::rt::resumable::Handle* h) {
                auto* xs = reinterpret_cast<int**>(alloca(stack * sizeof(char)));
                benchmark::DoNotOptimize(xs[stack - 1]);
                return hilti::rt::Nothing();
            }));
        }

        for ( auto& r : rs ) {
            state.ResumeTiming();
            r.resume();
            state.PauseTiming();
        }
    }
}

static void execute_many_resume(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        std::vector<hilti::rt::Resumable> rs;

        auto fibers = state.range(0);

        for ( int i = 0; i < fibers; ++i ) {
            rs.push_back(hilti::rt::Resumable([&](hilti::rt::resumable::Handle* h) {
                h->yield();
                return hilti::rt::Nothing();
            }));
        }

        for ( auto& r : rs ) {
            // Run fibers once.
            r.resume();

            state.ResumeTiming();
            r.resume();
            state.PauseTiming();
        }
    }
}

BENCHMARK(init);
BENCHMARK(done);

BENCHMARK(execute_one)->ArgName("stack")->Range(1, hilti::rt::detail::Fiber::StackSize / 2);
BENCHMARK(execute_one_yield)->ArgName("stack")->Range(1, hilti::rt::detail::Fiber::StackSize / 2);
BENCHMARK(execute_yield_to_other)->ArgName("stack")->Range(1, hilti::rt::detail::Fiber::StackSize / 2);

BENCHMARK(execute_many)
    ->ArgNames({"stack", "fibers"})
    ->Ranges({{1, hilti::rt::detail::Fiber::StackSize / 2}, {1, 4096}});

BENCHMARK(execute_many_resume)->ArgName("fibers")->Range(1, 4096);

BENCHMARK_MAIN();
