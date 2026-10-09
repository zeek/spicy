// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
#include <benchmark/benchmark.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#include <hilti/rt/libhilti.h>

#include <spicy/rt/libspicy.h>

#include "PIRBenchmark.h"
#include "parsing-input.h"

using namespace hilti::rt::string::literals;
using Result = hlt_internal_PIRBenchmark::_r__spicy_pir_backend::ParseResult_0;

static auto parse(std::uint64_t count) {
    auto stream = hilti::rt::reference::make_value<hilti::rt::Stream>(makeInput(count));
    stream->freeze();
    return hlt_internal_PIRBenchmark::_r__spicy_pir_backend::parse_root_0(stream, {});
}

static void benchmarkPir(benchmark::State& state) {
    hilti::rt::init();
    spicy::rt::init();

    const auto count = static_cast<std::uint64_t>(state.range(0));
    auto representative = parse(count);
    if ( representative.kind != hlt_internal_PIRBenchmark::_r__spicy_pir_backend::OutcomeKind::Success ||
         ! representative.unit || representative.cursor.offset() != count + 11 ||
         (*representative.unit)->field_1 != count || (*representative.unit)->field_2.size() != count ||
         (*representative.unit)->field_3 != "END"_b ) {
        state.SkipWithError("PIR result did not consume and publish the expected input");
        hilti::rt::done();
        return;
    }

    for ( auto _ : state ) {
        (void)_;
        state.PauseTiming();
        auto stream = hilti::rt::reference::make_value<hilti::rt::Stream>(makeInput(count));
        stream->freeze();
        state.ResumeTiming();
        auto result = hlt_internal_PIRBenchmark::_r__spicy_pir_backend::parse_root_0(stream, {});
        benchmark::DoNotOptimize(result);
    }

    hilti::rt::done();
}

BENCHMARK(benchmarkPir)->RangeMultiplier(10)->Range(100, 100000);

BENCHMARK_MAIN();
