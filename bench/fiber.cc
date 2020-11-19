#include <benchmark/benchmark.h>

#include <array>

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

template<size_t N>
static void execute_one(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto r = hilti::rt::Resumable([&](hilti::rt::resumable::Handle* h) {
            std::array<char, N> xs;
            benchmark::DoNotOptimize(xs[N - 1]);
            return hilti::rt::Nothing();
        });

        state.ResumeTiming();
        r.resume();
    }
}

template<size_t N>
static void execute_one_yield(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto r = hilti::rt::Resumable([](hilti::rt::resumable::Handle* h) {
            std::array<char, N> xs;
            benchmark::DoNotOptimize(xs[N - 1]);
            h->yield();
            benchmark::DoNotOptimize(xs[N - 1]);
            return hilti::rt::Nothing();
        });

        while ( ! r.hasResult() ) {
            state.ResumeTiming();
            r.resume();
            state.PauseTiming();
        }
    }
}

template<size_t N>
static void execute_yield_to_other(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        auto r1 = hilti::rt::Resumable([&](hilti::rt::resumable::Handle* h) {
            std::array<char, N> xs;
            benchmark::DoNotOptimize(xs[N - 1]);
            h->yield();
            benchmark::DoNotOptimize(xs[N - 1]);
            return hilti::rt::Nothing();
        });

        auto r2 = hilti::rt::Resumable([&](hilti::rt::resumable::Handle* h) {
            std::array<char, N> xs;
            benchmark::DoNotOptimize(xs[N - 1]);
            r1.resume();
            benchmark::DoNotOptimize(xs[N - 1]);
            return hilti::rt::Nothing();
        });

        while ( ! r2.hasResult() ) {
            state.ResumeTiming();
            r2.resume();
            state.PauseTiming();
        }
    }
}

template<size_t N>
static void execute_many(benchmark::State& state) {
    hilti::rt::done();
    hilti::rt::init();
    hilti::rt::detail::Fiber::primeCache();

    for ( auto _ : state ) {
        state.PauseTiming();

        std::vector<hilti::rt::Resumable> rs;

        for ( int i = 0; i < state.range(0); ++i ) {
            rs.push_back(hilti::rt::Resumable([&](hilti::rt::resumable::Handle* h) {
                std::array<char, N> xs;
                benchmark::DoNotOptimize(xs[N - 1]);
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

        for ( int i = 0; i < state.range(0); ++i ) {
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

BENCHMARK_TEMPLATE(execute_one, 1);
BENCHMARK_TEMPLATE(execute_one, 512);
BENCHMARK_TEMPLATE(execute_one, 4096);
BENCHMARK_TEMPLATE(execute_one, hilti::rt::detail::Fiber::StackSize / 8);
BENCHMARK_TEMPLATE(execute_one, hilti::rt::detail::Fiber::StackSize / 4);
BENCHMARK_TEMPLATE(execute_one, hilti::rt::detail::Fiber::StackSize / 2);

BENCHMARK_TEMPLATE(execute_one_yield, 1);
BENCHMARK_TEMPLATE(execute_one_yield, 512);
BENCHMARK_TEMPLATE(execute_one_yield, 4096);
BENCHMARK_TEMPLATE(execute_one_yield, hilti::rt::detail::Fiber::StackSize / 8);
BENCHMARK_TEMPLATE(execute_one_yield, hilti::rt::detail::Fiber::StackSize / 4);
BENCHMARK_TEMPLATE(execute_one_yield, hilti::rt::detail::Fiber::StackSize / 2);

BENCHMARK_TEMPLATE(execute_yield_to_other, 1);
BENCHMARK_TEMPLATE(execute_yield_to_other, 512);
BENCHMARK_TEMPLATE(execute_yield_to_other, 4096);
BENCHMARK_TEMPLATE(execute_yield_to_other, hilti::rt::detail::Fiber::StackSize / 8);
BENCHMARK_TEMPLATE(execute_yield_to_other, hilti::rt::detail::Fiber::StackSize / 4);
BENCHMARK_TEMPLATE(execute_yield_to_other, hilti::rt::detail::Fiber::StackSize / 2);

BENCHMARK_TEMPLATE(execute_many, 1)->Arg(1)->Arg(64)->Arg(512)->Arg(4096);
BENCHMARK_TEMPLATE(execute_many, 4096)->Arg(1)->Arg(64)->Arg(512)->Arg(4096);
BENCHMARK_TEMPLATE(execute_many, hilti::rt::detail::Fiber::StackSize / 2)->Arg(1)->Arg(64)->Arg(512)->Arg(4096);

BENCHMARK(execute_many_resume)->Arg(1)->Arg(64)->Arg(512)->Arg(4096);

BENCHMARK_MAIN();
