// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cstdint>

#include <hilti/rt/init.h>
#include <hilti/rt/types/bytes.h>
#include <hilti/rt/types/map.h>
#include <hilti/rt/types/set.h>
#include <hilti/rt/types/vector.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#include <benchmark/benchmark.h>
#pragma GCC diagnostic pop

static void iterate_bytes(benchmark::State& state) {
    hilti::rt::init();

    auto len = state.range();

    const auto data = hilti::rt::Bytes(static_cast<size_t>(len), '\n');

    // NOLINTNEXTLINE
    for ( auto _ : state ) {
        for ( const auto& c : data )
            benchmark::DoNotOptimize(c + 1);
    }
}

static void iterate_map(benchmark::State& state) {
    hilti::rt::init();

    auto len = state.range();

    auto data = hilti::rt::Map<int64_t, int64_t>();
    for ( auto i = 0; i < len; ++i )
        data.index_assign(i, i);

    // NOLINTNEXTLINE
    for ( auto _ : state ) {
        for ( const auto& [k, v] : data ) {
            benchmark::DoNotOptimize(k + 1);
        }
    }
}

static void iterate_set(benchmark::State& state) {
    hilti::rt::init();

    auto len = state.range();

    auto data = hilti::rt::Set<int64_t>();
    for ( auto i = 0; i < len; ++i )
        data.insert(i);

    // NOLINTNEXTLINE
    for ( auto _ : state ) {
        for ( const auto& c : data )
            benchmark::DoNotOptimize(c + 1);
    }
}

static void iterate_vector(benchmark::State& state) {
    hilti::rt::init();

    auto len = state.range();

    auto data = hilti::rt::Vector<int64_t>();
    for ( auto i = 0; i < len; ++i )
        data.push_back(i);

    // NOLINTNEXTLINE
    for ( auto _ : state ) {
        for ( const auto& c : data )
            benchmark::DoNotOptimize(c + 1);
    }
}

BENCHMARK(iterate_bytes)->ArgName("len")->RangeMultiplier(100)->Range(1, 1'000'000);
BENCHMARK(iterate_map)->ArgName("len")->RangeMultiplier(100)->Range(1, 1'000'000);
BENCHMARK(iterate_set)->ArgName("len")->RangeMultiplier(100)->Range(1, 1'000'000);
BENCHMARK(iterate_vector)->ArgName("len")->RangeMultiplier(100)->Range(1, 1'000'000);
