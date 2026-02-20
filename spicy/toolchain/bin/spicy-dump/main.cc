// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <getopt.h>

#include <fstream>
#include <iostream>

#include <hilti/rt/init.h>
#include <hilti/rt/libhilti.h>

#include <spicy/rt/libspicy.h>

#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

#include <spicy/compiler/init.h>
#include <spicy/spicy.h>

#include "options.h"
#include "printer-json.h"
#include "printer-text.h"

using spicy::rt::fmt;

constexpr int OptStrictPublicAPI = 1000;
constexpr int OptNoStrictPublicAPI = 1001;

static struct option long_options[] = {

    {.name = "abort-on-exceptions", .has_arg = required_argument, .flag = nullptr, .val = 'A'},
    {.name = "compiler-debug", .has_arg = required_argument, .flag = nullptr, .val = 'D'},
    {.name = "debug", .has_arg = no_argument, .flag = nullptr, .val = 'd'},
    {.name = "debug-addl", .has_arg = required_argument, .flag = nullptr, .val = 'X'},
    {.name = "enable-print", .has_arg = no_argument, .flag = nullptr, .val = 'P'},
    {.name = "enable-profiling", .has_arg = no_argument, .flag = nullptr, .val = 'Z'},
    {.name = "file", .has_arg = required_argument, .flag = nullptr, .val = 'f'},
    {.name = "help", .has_arg = no_argument, .flag = nullptr, .val = 'h'},
    {.name = "json", .has_arg = no_argument, .flag = nullptr, .val = 'J'},
    {.name = "library-path", .has_arg = required_argument, .flag = nullptr, .val = 'L'},
    {.name = "list-parsers", .has_arg = no_argument, .flag = nullptr, .val = 'l'},
    {.name = "parser", .has_arg = required_argument, .flag = nullptr, .val = 'p'},
    {.name = "report-times", .has_arg = required_argument, .flag = nullptr, .val = 'R'},
    {.name = "show-backtraces", .has_arg = required_argument, .flag = nullptr, .val = 'B'},
    {.name = "skip-dependencies", .has_arg = no_argument, .flag = nullptr, .val = 'S'},
    {.name = "version", .has_arg = no_argument, .flag = nullptr, .val = 'v'},
    {.name = "strict-public-api", .has_arg = no_argument, .flag = nullptr, .val = OptStrictPublicAPI},
    {.name = "no-strict-public-api", .has_arg = no_argument, .flag = nullptr, .val = OptNoStrictPublicAPI},
    {.name = nullptr, .has_arg = 0, .flag = nullptr, .val = 0},

};

static void fatalError(const std::string& msg) {
    hilti::logger().error(fmt("spicy-dump: %s", msg));
    spicy::rt::done();
    hilti::rt::done();
    exit(1);
}

class SpicyDump : public spicy::Driver, public spicy::rt::Driver {
public:
    SpicyDump() : spicy::Driver("spicy-dump", hilti::util::currentExecutable()) {
        spicy::Configuration::extendHiltiConfiguration();
    }

    void parseOptions(int argc, char** argv);
    void usage();

    bool opt_json = false;
    int opt_list_parsers = 0;
    bool opt_enable_print = false;
    std::string opt_file = "/dev/stdin";
    std::string opt_parser;
    OutputOptions output_options;

private:
    void hookInitRuntime() override { spicy::rt::init(); }
    void hookFinishRuntime() override { spicy::rt::done(); }
};

void SpicyDump::usage() {
    auto exts = hilti::util::join(hilti::plugin::registry().supportedExtensions(), ", ");

    std::cerr
        << "Usage: cat <data> | spicy-dump [options] <inputs> ...\n"
           "\n"
           "Options:\n"
           "\n"
           "  -d | --debug                    Include debug instrumentation into generated code.\n"
           "  -f | --file <path>              Read input from <path> instead of stdin.\n"
           "  -l | --list-parsers             List available parsers and exit; use twice to include aliases.\n"
           "  -p | --parser <name>            Use parser <name> to process input. Only needed if more than one parser "
           "is available.\n"
           "  -v | --version                  Print version information.\n"
           "  -A | --abort-on-exceptions      When executing compiled code, abort() instead of throwing HILTI "
           "exceptions.\n"
           "  -B | --show-backtraces          Include backtraces when reporting unhandled exceptions.\n"
           "  -D | --compiler-debug <streams> Activate compile-time debugging output for given debug streams "
           "(comma-separated; 'help' for list).\n"
           "  -L | --library-path <path>      Add path to list of directories to search when importing modules.\n"
           "  -J | --json                     Print JSON output.\n"
           "  -P | --enable-print             Show output of Spicy 'print' statements (default: off).\n"
           "  -Q | --include-offsets          Include stream offsets of parsed data in output.\n"
           "  -R | --report-times             Report a break-down of compiler's execution time.\n"
           "  -S | --skip-dependencies        Do not automatically compile dependencies during JIT.\n"
           "  -X | --debug-addl <addl>        Implies -d and adds selected additional instrumentation "
           "(comma-separated; see 'help' for list).\n"
           "  -Z | --enable-profiling         Report profiling statistics after execution.\n"
           "       --strict-public-api        Skip optimizations that change the public C++ API of generated code.\n"
           "       --no-strict-public-api     Allow optimizations that change the public C++ API of generated code.\n"
           "\n"
           "Environment variables:\n"
           "\n"
           "  SPICY_PATH                      Colon-separated list of directories to search for modules. In contrast "
           "to --library-paths using this flag overwrites builtin paths.\n"
           "\n"
           "Inputs can be "
        << exts
        << ", *.spicy *.hlt *.hlto.\n"
           "\n";
}

/** TODO(robin): Can we factor out common option handling to the Spicy driver? */
void SpicyDump::parseOptions(int argc, char** argv) {
    hilti::driver::Options driver_options;
    hilti::Options hilti_compiler_options;
    spicy::Options spicy_compiler_options;

    driver_options.execute_code = true;
    driver_options.include_linker = true;
    driver_options.logger = std::make_unique<hilti::Logger>();

    while ( true ) {
        int c = getopt_long(argc, argv, "BAD:f:hdX:QVlp:PSRL:JZ", long_options, nullptr);

        if ( c < 0 )
            break;

        switch ( c ) {
            case 'A': driver_options.abort_on_exceptions = true; break;

            case 'B': driver_options.show_backtraces = true; break;

            case 'd': {
                hilti_compiler_options.debug = true;
                break;
            }

            case 'f': {
                opt_file = optarg;
                break;
            }

            case 'X': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cerr << "Additional debug instrumentation:\n";
                    std::cerr << "   flow:     log function calls to debug stream \"hilti-flow\"\n";
                    std::cerr << "   location: log statements to debug stream \"hilti-trace\"\n";
                    std::cerr << "   trace:    track current source code location for error reporting\n";
                    std::cerr << "\n";
                    exit(0);
                }

                hilti_compiler_options.debug = true;

                if ( auto r = hilti_compiler_options.parseDebugAddl(arg); ! r )
                    fatalError(r.error());

                break;
            }

            case 'D': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cerr << "Debug streams:\n";

                    for ( const auto& s : hilti::logging::DebugStream::all() )
                        std::cerr << "  " << s << "\n";

                    std::cerr << "\n";
                    exit(0);
                }

                for ( const auto& s : hilti::util::split(arg, ",") ) {
                    if ( ! driver_options.logger->debugEnable(s) )
                        fatalError(fmt("unknown debug stream '%s', use 'help' for list", arg));
                }

                break;
            }

            case 'J': opt_json = true; break;

            case 'Q':
                spicy_compiler_options.track_offsets = true;
                output_options.include_offsets = true;
                break;

            case 'l': ++opt_list_parsers; break;

            case 'p': opt_parser = optarg; break;

            case 'P': opt_enable_print = true; break;

            case 'R': driver_options.report_times = true; break;

            case 'S': driver_options.skip_dependencies = true; break;

            case 'v': std::cerr << "spicy-dump v" << hilti::configuration().version_string_long << '\n'; exit(0);

            case 'Z':
                hilti_compiler_options.enable_profiling = true;
                driver_options.enable_profiling = true;
                break;

            case OptStrictPublicAPI:
                hilti_compiler_options.public_api_mode = hilti::Options::PublicAPIMode::Strict;
                break;

            case OptNoStrictPublicAPI:
                hilti_compiler_options.public_api_mode = hilti::Options::PublicAPIMode::NonStrict;
                break;

            case 'h': usage(); exit(0);

            case 'L': hilti_compiler_options.library_paths.emplace_back(optarg); break;

            default: usage(); fatalError(fmt("option %c not supported", c));
        }
    }

    setCompilerOptions(std::move(hilti_compiler_options));
    setSpicyCompilerOptions(spicy_compiler_options);
    setDriverOptions(std::move(driver_options));

    initialize();

    while ( optind < argc ) {
        if ( auto rc = addInput(argv[optind++]); ! rc )
            fatalError(rc.error().description());
    }
}

int main(int argc, char** argv) try {
    hilti::init();
    spicy::init();

    SpicyDump driver;

    driver.parseOptions(argc, argv);

    if ( auto x = driver.compile(); ! x )
        // The main error messages have been reported already at this point.
        // The returned error will have some more info about which pass
        // failed in its description, however that's less interesting to the
        // user so we're just reporting a generic message here.
        fatalError("aborting after errors");

    auto config = hilti::rt::configuration::get();

    if ( ! driver.opt_enable_print )
        config.cout.reset();

    hilti::rt::configuration::set(std::move(config));

    if ( auto x = driver.initRuntime(); ! x )
        fatalError(x.error().description());

    if ( driver.opt_list_parsers )
        driver.listParsers(std::cout, driver.opt_list_parsers > 1);

    else {
        auto parser = driver.lookupParser(driver.opt_parser);
        if ( ! parser )
            fatalError(parser.error());

        std::ifstream in(driver.opt_file, std::ios::in | std::ios::binary);

        if ( ! in.is_open() )
            fatalError("cannot open stdin for reading");

        auto unit = driver.processInput(**parser, in);
        if ( ! unit )
            fatalError(unit.error());

        if ( driver.opt_json )
            JSONPrinter(std::cout, driver.output_options).print(unit->value());
        else {
            TextPrinter(std::cout, driver.output_options).print(unit->value());
            std::cout << '\n';
        }
    }

    driver.finishRuntime();

    return 0;
} catch ( const std::exception& e ) {
    std::cerr << hilti::util::fmt("[fatal error] terminating with uncaught exception of type %s: %s",
                                  hilti::util::demangle(typeid(e).name()), e.what())
              << '\n';
    exit(1);
}
