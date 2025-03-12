// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <benchmark/benchmark.h>

#include <hilti/rt/init.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/stream.h>

#include <spicy/rt/init.h>
#include <spicy/rt/parsed-unit.h>
#include <spicy/rt/parser.h>

static std::string big_endian(std::uint64_t number) {
    char buffer[8];
    for ( int i = 0; i < 8; ++i ) {
        buffer[i] = static_cast<char>((number >> (56 - 8 * i)) & 0xFF);
    }
    return std::string(buffer, sizeof(buffer));
}

static std::string make_input(std::uint64_t input_size) {
    std::string number = big_endian(input_size);
    std::string repeated(input_size, 'A');
    return number + repeated + 'B' + 'B';
}

template<class... Args>
static void benchmark_parser(benchmark::State& state, Args&&... args) {
    auto args_tuple = std::make_tuple(std::move(args)...);
    auto parser_name = std::get<0>(args_tuple);

    hilti::rt::init();
    spicy::rt::init();

    const spicy::rt::Parser* parser = nullptr;
    for ( auto* p : spicy::rt::parsers() ) {
        if ( p->name == parser_name ) {
            parser = p;
            break;
        }
    }

    assert(parser);

    for ( auto _ : state ) {
        (void)_;
        state.PauseTiming();
        auto in = make_input(state.range(0));
        auto stream = hilti::rt::reference::make_value<hilti::rt::Stream>(in);
        stream->freeze();
        state.ResumeTiming();
        parser->parse1(stream, {}, {});
    }

    hilti::rt::done();
}

static const int64_t min_input = 100;
static const int64_t max_input = 100000;
static const int64_t mult = 10;

BENCHMARK_CAPTURE(benchmark_parser, Benchmark::UnitVectorSize, std::string("Benchmark::UnitVectorSize"))
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmark_parser, Benchmark::UnitVectorLookahead, std::string("Benchmark::UnitVectorLookahead"))
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_CAPTURE(benchmark_parser, Benchmark::Regex, std::string("Benchmark::Regex"))
    ->RangeMultiplier(mult)
    ->Range(min_input, max_input);

BENCHMARK_MAIN();
