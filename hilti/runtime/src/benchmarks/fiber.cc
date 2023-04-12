// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <benchmark/benchmark.h>

#include <cstdlib>

#include <hilti/rt/configuration.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/init.h>
#include <hilti/rt/result.h>

static void execute_one(benchmark::State& state) {
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        (void)_;
        state.PauseTiming();

        auto addl_stack_usage = state.range(0);
        auto r = hilti::rt::Resumable([addl_stack_usage](hilti::rt::resumable::Handle* h) {
            auto* xs = reinterpret_cast<char*>(alloca(addl_stack_usage));
            benchmark::DoNotOptimize(xs[addl_stack_usage - 1]);
            return hilti::rt::Nothing();
        });

        state.ResumeTiming();
        r.run();
        assert(r); // must have finished
    }

    hilti::rt::done();
}

static void execute_one_yield(benchmark::State& state) {
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        (void)_;
        state.PauseTiming();

        auto addl_stack_usage = state.range(0);
        auto r = hilti::rt::Resumable([addl_stack_usage](hilti::rt::resumable::Handle* h) {
            auto* xs = reinterpret_cast<char*>(alloca(addl_stack_usage));
            benchmark::DoNotOptimize(xs[addl_stack_usage - 1]);
            h->yield();
            return hilti::rt::Nothing();
        });

        state.ResumeTiming();
        r.run();
        r.resume();
        assert(r); // must have finished
    }

    hilti::rt::done();
}

static void execute_yield_to_other(benchmark::State& state) {
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        (void)_;
        state.PauseTiming();

        auto addl_stack_usage = state.range(0);
        auto r = hilti::rt::Resumable([addl_stack_usage, &state](hilti::rt::resumable::Handle* h) {
            state.PauseTiming();

            auto s = hilti::rt::Resumable([addl_stack_usage](hilti::rt::resumable::Handle* h) {
                auto* xs = reinterpret_cast<char*>(alloca(addl_stack_usage));
                benchmark::DoNotOptimize(xs[addl_stack_usage - 1]);
                h->yield();
                return hilti::rt::Nothing();
            });

            auto* xs = reinterpret_cast<char*>(alloca(addl_stack_usage));
            benchmark::DoNotOptimize(xs[addl_stack_usage - 1]);

            state.ResumeTiming();
            s.run();
            h->yield();
            s.resume();
            assert(s); // must have finished
            return hilti::rt::Nothing();
        });

        state.ResumeTiming();
        r.run();
        r.resume();
        assert(r); // must have finished
    }

    hilti::rt::done();
}

static void execute_many(benchmark::State& state) {
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        (void)_;
        state.PauseTiming();

        auto addl_stack_usage = state.range(0);
        auto num_fibers = state.range(1);

        std::vector<hilti::rt::Resumable> rs;

        rs.reserve(num_fibers);
        for ( int i = 0; i < num_fibers; ++i ) {
            rs.emplace_back([addl_stack_usage](hilti::rt::resumable::Handle* h) {
                auto* xs = reinterpret_cast<char*>(alloca(addl_stack_usage));
                benchmark::DoNotOptimize(xs[addl_stack_usage - 1]);
                return hilti::rt::Nothing();
            });
        }

        state.ResumeTiming();
        for ( auto& r : rs ) {
            r.run();
            assert(r); // must have finished
        }
    }

    hilti::rt::done();
}

static void execute_many_resume(benchmark::State& state) {
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        (void)_;
        state.PauseTiming();

        auto addl_stack_usage = state.range(0);
        auto num_fibers = state.range(1);

        std::vector<hilti::rt::Resumable> rs;

        rs.reserve(num_fibers);
        for ( int i = 0; i < num_fibers; ++i ) {
            rs.emplace_back([addl_stack_usage](hilti::rt::resumable::Handle* h) {
                auto* xs = reinterpret_cast<char*>(alloca(addl_stack_usage));
                benchmark::DoNotOptimize(xs[addl_stack_usage - 1]);
                h->yield();
                return hilti::rt::Nothing();
            });
        }

        state.ResumeTiming();
        for ( auto& r : rs )
            r.run();

        for ( auto& r : rs ) {
            r.resume();
            assert(r); // must have finished
        }
    }

    hilti::rt::done();
}

const auto addl_stack_usage =
    static_cast<int64_t>(static_cast<double>(hilti::rt::configuration::get().fiber_min_stack_size) * 0.9);

BENCHMARK(execute_one)->ArgName("addl_stack_usage")->Range(1, addl_stack_usage);
BENCHMARK(execute_one_yield)->ArgName("addl_stack_usage")->Range(1, addl_stack_usage);
BENCHMARK(execute_yield_to_other)->ArgName("addl_stack_usage")->Range(1, addl_stack_usage);
BENCHMARK(execute_many)->ArgNames({"addl_stack_usage", "fibers"})->Ranges({{1, addl_stack_usage}, {1, 4096}});
BENCHMARK(execute_many_resume)->ArgNames({"addl_stack_usage", "fibers"})->Ranges({{1, addl_stack_usage}, {1, 4096}});

BENCHMARK_MAIN();
