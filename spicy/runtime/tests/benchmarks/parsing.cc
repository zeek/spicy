// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#endif
#include <benchmark/benchmark.h>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#include <hilti/rt/init.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

#include <spicy/rt/init.h>
#include <spicy/rt/parsed-unit.h>
#include <spicy/rt/parser.h>

#include "parsing-input.h"

using namespace hilti::rt::string::literals;

static std::string makeSwitchInput(std::uint64_t entry_count) {
    // Each entry: 1-byte tag + variable payload (tag cycles 1-4).
    // tag=1: 1+1=2 bytes, tag=2: 1+2=3, tag=3: 1+4=5, tag=4(*): 1+8=9
    std::string entries;
    for ( std::uint64_t i = 0; i < entry_count; ++i ) {
        char tag = static_cast<char>((i % 4) + 1);
        entries += tag;
        std::size_t payload_size = (tag <= 3) ? (1U << (tag - 1)) : 8;
        entries += std::string(payload_size, '\x01');
    }
    return bigEndian(entries.size()) + entries;
}

static std::string makeNestedInput(std::uint64_t entry_count) {
    // Each Middle: Inner(Leaf(2) + Leaf(2)) + uint16 = 6 bytes
    std::string entries(entry_count * 6, '\x01');
    return bigEndian(entries.size()) + entries;
}

static std::string makeBytesInput(std::uint64_t entry_count) {
    // Each entry: 1-byte length + payload. Use fixed 8-byte payloads.
    std::string entries;
    for ( std::uint64_t i = 0; i < entry_count; ++i ) {
        entries += '\x08';
        entries += std::string(8, 'B');
    }
    return bigEndian(entries.size()) + entries;
}

template<class... Args>
static void benchmarkParser(benchmark::State& state, Args&&... args) {
    auto args_tuple = std::make_tuple(std::move(args)...);
    const auto& parser_name = std::get<0>(args_tuple);
    auto make_input = std::get<1>(args_tuple);

    hilti::rt::init();
    spicy::rt::init();

    const spicy::rt::Parser* parser = nullptr;
    for ( const auto* p : spicy::rt::parsers() ) {
        if ( p->name == parser_name ) {
            parser = p;
            break;
        }
    }

    if ( ! parser )
        hilti::rt::fatalError(hilti::rt::fmt("parser %s not found", parser_name));

    if ( parser->name == "Benchmark::UnitVectorSize"_hs ) {
        auto stream = hilti::rt::reference::make_value<hilti::rt::Stream>(make_input(state.range(0)));
        stream->freeze();
        auto cursor = parser->parse1(stream, {}, {}).template get<hilti::rt::stream::View>();
        if ( cursor.offset() != static_cast<std::uint64_t>(state.range(0)) + 11 ) {
            state.SkipWithError("legacy result did not consume the expected input");
            hilti::rt::done();
            return;
        }
    }

    for ( auto _ : state ) {
        (void)_;
        state.PauseTiming();
        auto in = make_input(state.range(0));
        auto stream = hilti::rt::reference::make_value<hilti::rt::Stream>(in);
        stream->freeze();
        state.ResumeTiming();
        auto cursor = parser->parse1(stream, {}, {}).template get<hilti::rt::stream::View>();
        benchmark::DoNotOptimize(cursor);
    }

    hilti::rt::done();
}

static const int64_t min_input = 100;
static const int64_t max_input = 100000;
static const int64_t mult = 10;

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::UnitVectorSize, "Benchmark::UnitVectorSize"_hs, makeInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::UnitVectorLookahead, "BenchmarkOther::UnitVectorLookahead"_hs, makeInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::Regex, "BenchmarkOther::Regex"_hs, makeInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::UnitSwitch, "BenchmarkOther::UnitSwitch"_hs, makeSwitchInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::UnitNested, "BenchmarkOther::UnitNested"_hs, makeNestedInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::UnitBytes, "BenchmarkOther::UnitBytes"_hs, makeBytesInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_MAIN();
