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

static std::uint64_t expectedInput(std::int64_t count) { return count + 11; }

static std::uint64_t expectedSwitch(std::int64_t count) { return makeSwitchInput(count).size(); }

static std::uint64_t expectedNested(std::int64_t count) { return makeNestedInput(count).size(); }

static std::uint64_t expectedBytes(std::int64_t count) { return makeBytesInput(count).size(); }

// Initialize once per process. PIR-compiled modules keep their parser in module globals, which
// `done()` destroys while the registry still points at it, so re-initializing per benchmark breaks
// the parser lookup.
static void initRuntime() {
    static const bool initialized = [] {
        hilti::rt::init();
        spicy::rt::init();
        std::atexit(hilti::rt::done);
        return true;
    }();
    (void)initialized;
}

template<class... Args>
static void benchmarkParser(benchmark::State& state, Args&&... args) {
    auto args_tuple = std::make_tuple(std::move(args)...);
    const auto& parser_name = std::get<0>(args_tuple);
    auto make_input = std::get<1>(args_tuple);
    auto expected_offset = std::get<2>(args_tuple);

    initRuntime();

    const spicy::rt::Parser* parser = nullptr;
    for ( const auto* p : spicy::rt::parsers() ) {
        if ( p->name == parser_name ) {
            parser = p;
            break;
        }
    }

    if ( ! parser ) {
        state.SkipWithError(hilti::rt::fmt("parser %s not available", parser_name).c_str());
        return;
    }

    const auto input_size = expected_offset(state.range(0));

    {
        auto stream = hilti::rt::reference::make_value<hilti::rt::Stream>(make_input(state.range(0)));
        stream->freeze();
        auto cursor = parser->parse1(stream, {}, {}).template get<hilti::rt::stream::View>();
        if ( cursor.offset() != input_size ) {
            state.SkipWithError("parser did not consume the expected input");
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

    state.SetBytesProcessed(state.iterations() * input_size);
}

static const int64_t min_input = 100;
static const int64_t max_input = 100000;
static const int64_t mult = 10;

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::UnitVectorSize, "Benchmark::UnitVectorSize"_hs, makeInput, expectedInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser,
                  Benchmark::UnitVectorLookahead,
                  "BenchmarkLookahead::UnitVectorLookahead"_hs,
                  makeInput,
                  expectedInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::Regex, "BenchmarkRegex::Regex"_hs, makeInput, expectedInput)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser,
                  Benchmark::UnitSwitch,
                  "BenchmarkSwitch::UnitSwitch"_hs,
                  makeSwitchInput,
                  expectedSwitch)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser,
                  Benchmark::UnitNested,
                  "BenchmarkNested::UnitNested"_hs,
                  makeNestedInput,
                  expectedNested)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmarkParser, Benchmark::UnitBytes, "BenchmarkBytes::UnitBytes"_hs, makeBytesInput, expectedBytes)
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_MAIN();
