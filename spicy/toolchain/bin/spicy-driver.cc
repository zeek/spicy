// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <getopt.h>

#include <fstream>
#include <iostream>
#include <ranges>

#include <hilti/rt/libhilti.h>

#include <spicy/rt/libspicy.h>

#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

#include <spicy/compiler/init.h>
#include <spicy/spicy.h>

using spicy::rt::fmt;

static struct option long_driver_options[] = {
    {.name = "abort-on-exceptions", .has_arg = required_argument, .flag = nullptr, .val = 'A'},
    {.name = "require-accept", .has_arg = no_argument, .flag = nullptr, .val = 'c'},
    {.name = "compiler-debug", .has_arg = required_argument, .flag = nullptr, .val = 'D'},
    {.name = "debug", .has_arg = no_argument, .flag = nullptr, .val = 'd'},
    {.name = "debug-addl", .has_arg = required_argument, .flag = nullptr, .val = 'X'},
    {.name = "disable-optimizations", .has_arg = no_argument, .flag = nullptr, .val = 'g'},
    {.name = "enable-profiling", .has_arg = no_argument, .flag = nullptr, .val = 'Z'},
    {.name = "file", .has_arg = required_argument, .flag = nullptr, .val = 'f'},
    {.name = "batch-file", .has_arg = required_argument, .flag = nullptr, .val = 'F'},
    {.name = "help", .has_arg = no_argument, .flag = nullptr, .val = 'h'},
    {.name = "increment", .has_arg = required_argument, .flag = nullptr, .val = 'i'},
    {.name = "library-path", .has_arg = required_argument, .flag = nullptr, .val = 'L'},
    {.name = "list-parsers", .has_arg = no_argument, .flag = nullptr, .val = 'l'},
    {.name = "parser", .has_arg = required_argument, .flag = nullptr, .val = 'p'},
    {.name = "parser-alias", .has_arg = required_argument, .flag = nullptr, .val = 'P'},
    {.name = "report-times", .has_arg = required_argument, .flag = nullptr, .val = 'R'},
    {.name = "show-backtraces", .has_arg = required_argument, .flag = nullptr, .val = 'B'},
    {.name = "skip-dependencies", .has_arg = no_argument, .flag = nullptr, .val = 'S'},
    {.name = "report-resource-usage", .has_arg = no_argument, .flag = nullptr, .val = 'U'},
    {.name = "skip-validation", .has_arg = no_argument, .flag = nullptr, .val = 'V'},
    {.name = "version", .has_arg = no_argument, .flag = nullptr, .val = 'v'},
    {.name = nullptr, .has_arg = 0, .flag = nullptr, .val = 0},
};

static bool require_accept = false; // --require-accept

static bool accepted = false; // set by hook_accept_input()
static void hookAcceptInput() { accepted = true; }

static bool declined = false; // set by hook_decline_input()
static void hookDeclineInput(const std::string& reason) { declined = true; }

class SpicyDriver : public spicy::Driver, public spicy::rt::Driver {
public:
    explicit SpicyDriver() : spicy::Driver("spicy-driver", hilti::util::currentExecutable()) {
        spicy::Configuration::extendHiltiConfiguration();
    }

    void parseOptions(int argc, char** argv);
    void usage();

    int opt_list_parsers = 0;
    int opt_increment = 0;
    bool opt_input_is_batch = false;
    std::string opt_file = "/dev/stdin";
    std::string opt_parser;
    std::vector<std::string> opt_parser_aliases;

private:
    void hookInitRuntime() override { spicy::rt::init(); }
    void hookFinishRuntime() override { spicy::rt::done(); }
};

void SpicyDriver::usage() {
    auto exts = hilti::util::join(hilti::plugin::registry().supportedExtensions(), ", ");

    std::cout
        << "Usage: cat <data> | spicy-driver [options] <inputs> ...\n"
           "\n"
           "Options:\n"
           "\n"
           "  -c | --require-accept               Return failure exit code if parser did not call accept_input(), or "
           "called "
           "decline_input().\n"
           "  -d | --debug                        Include debug instrumentation into generated code.\n"
           "  -g | --disable-optimizations        Disable HILTI-side optimizations of the generated code.\n"
           "  -i | --increment <i>                Feed data incrementally in chunks of size n.\n"
           "  -f | --file <path>                  Read input from <path> instead of stdin.\n"
           "  -l | --list-parsers                 List available parsers and exit; use twice to include aliases.\n"
           "  -p | --parser <name>                Use parser <name> to process input. Only needed if more than one "
           "parser "
           "is available.\n"
           "  -v | --version                      Print version information.\n"
           "  -A | --abort-on-exceptions          When executing compiled code, abort() instead of throwing HILTI "
           "exceptions.\n"
           "  -B | --show-backtraces              Include backtraces when reporting unhandled exceptions.\n"
           "  -D | --compiler-debug <streams>     Activate compile-time debugging output for given debug streams "
           "(comma-separated; 'help' for list).\n"
           "  -F | --batch-file <path>            Read Spicy batch input from <path>; see docs for description of "
           "format.\n"
           "  -L | --library-path <path>          Add path to list of directories to search when importing modules.\n"
           "  -P | --parser-alias <alias>=<name>  Add alias name for parser of existing name.\n"
           "  -R | --report-times                 Report a break-down of compiler's execution time.\n"
           "  -S | --skip-dependencies            Do not automatically compile dependencies during JIT.\n"
           "  -U | --report-resource-usage        Print summary of runtime resource usage.\n"
           "  -V | --skip-validation              Don't validate ASTs (for debugging only).\n"
           "  -X | --debug-addl <addl>            Implies -d and adds selected additional instrumentation "
           "(comma-separated; see 'help' for list).\n"
           "  -Z | --enable-profiling             Report profiling statistics after execution.\n"
           "\n"
           "Environment variables:\n"
           "\n"
           "  SPICY_PATH                      Colon-separated list of directories to search for modules. In contrast "
           "to --library-paths using this flag overwrites builtin paths.\n"
           "\n"
           "Inputs can be "
        << exts
        << ", .cc/.cxx, *.o, *.hlto.\n"
           "\n";
}

void SpicyDriver::parseOptions(int argc, char** argv) {
    hilti::driver::Options driver_options;
    hilti::Options compiler_options;

    driver_options.execute_code = true;
    driver_options.include_linker = true;
    driver_options.logger = std::make_unique<hilti::Logger>();

    while ( true ) {
        int c = getopt_long(argc, argv, "ABcD:f:F:ghdJX:Vlp:P:i:SRL:UVZ", long_driver_options, nullptr);

        if ( c < 0 )
            break;

        switch ( c ) {
            case 'A': driver_options.abort_on_exceptions = true; break;

            case 'B': driver_options.show_backtraces = true; break;

            case 'c': {
                require_accept = true;
                break;
            }

            case 'd': {
                compiler_options.debug = true;
                break;
            }

            case 'f': {
                opt_file = optarg;
                break;
            }

            case 'F': {
                opt_file = optarg;
                opt_input_is_batch = true;
                break;
            }

            case 'g': {
                compiler_options.global_optimizations = false;
                break;
            }

            case 'X': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cout << "Additional debug instrumentation:\n";
                    std::cout << "   flow:     log function calls to debug stream \"hilti-flow\"\n";
                    std::cout << "   location: log statements to debug stream \"hilti-trace\"\n";
                    std::cout << "   trace:    track current source code location for error reporting\n";
                    std::cout << "\n";
                    exit(0);
                }

                compiler_options.debug = true;

                if ( auto r = compiler_options.parseDebugAddl(arg); ! r )
                    fatalError(r.error());

                break;
            }

            case 'J': {
                driver_options.execute_code = false;
                break;
            }

            case 'D': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cout << "Debug streams:\n";

                    for ( const auto& s : hilti::logging::DebugStream::all() )
                        std::cout << "  " << s << "\n";

                    std::cout << "\n";
                    exit(0);
                }

                for ( const auto& s : hilti::util::split(arg, ",") ) {
                    if ( ! driver_options.logger->debugEnable(s) )
                        fatalError(fmt("unknown debug stream '%s', use 'help' for list", arg));
                }

                break;
            }

            case 'i':
                opt_increment = atoi(optarg); // NOLINT
                break;

            case 'l': ++opt_list_parsers; break;

            case 'p': opt_parser = optarg; break;

            case 'P': opt_parser_aliases.emplace_back(optarg); break;

            case 'R': driver_options.report_times = true; break;

            case 'S': driver_options.skip_dependencies = true; break;

            case 'U': driver_options.report_resource_usage = true; break;

            case 'v': std::cout << "spicy-driver v" << hilti::configuration().version_string_long << '\n'; exit(0);

            case 'L': compiler_options.library_paths.emplace_back(optarg); break;

            case 'V': compiler_options.skip_validation = true; break;

            case 'Z':
                compiler_options.enable_profiling = true;
                driver_options.enable_profiling = true;
                break;

            case 'h': usage(); exit(0);
            case '?': [[fallthrough]];
            default:
                if ( optopt )
                    fatalError(fmt("option '%s' requires an argument; try --help for usage", argv[optind - 1]));
                else
                    fatalError(fmt("option '%s' not supported; try --help for usage", argv[optind - 1]));
        }
    }

    setCompilerOptions(std::move(compiler_options));
    setDriverOptions(std::move(driver_options));

    initialize();

    while ( optind < argc ) {
        if ( auto rc = addInput(argv[optind++]); ! rc )
            fatalError(rc.error());
    }
}

int main(int argc, char** argv) try {
    hilti::init();
    spicy::init();

    auto config = spicy::rt::configuration::get();
    config.hook_accept_input = hookAcceptInput;
    config.hook_decline_input = hookDeclineInput;
    spicy::rt::configuration::set(config);

    SpicyDriver driver;

    driver.parseOptions(argc, argv);

    if ( auto x = driver.compile(); ! x )
        driver.fatalError(x.error());

    if ( auto x = driver.initRuntime(); ! x )
        driver.fatalError(x.error());

    for ( const auto& parser : driver.opt_parser_aliases ) {
        auto m = std::ranges::transform_view(hilti::util::split(parser, "="),
                                             [](const auto& x) { return hilti::util::trim(x); });

        if ( m.size() != 2 )
            driver.fatalError("invalid alias specification: must be of form '<alias>=<parser-name>'");

        if ( auto rc = spicy::rt::registerParserAlias(m[1], m[0]); ! rc )
            driver.fatalError(fmt("invalid alias specification: %s", rc.error()));
    }

    if ( driver.opt_list_parsers )
        driver.listParsers(std::cout, driver.opt_list_parsers > 1);

    else {
        std::ifstream in(driver.opt_file, std::ios::in | std::ios::binary);

        if ( ! in.is_open() )
            driver.fatalError("cannot open input for reading");

        if ( driver.opt_input_is_batch ) {
            if ( auto x = driver.processPreBatchedInput(in); ! x )
                driver.fatalError(x.error());
        }
        else {
            auto parser = driver.lookupParser(driver.opt_parser);
            if ( ! parser )
                driver.fatalError(parser.error());

            if ( auto x = driver.processInput(**parser, in, driver.opt_increment); ! x )
                driver.fatalError(x.error());
        }
    }

    driver.finishRuntime();

    if ( driver.driverOptions().report_times )
        hilti::util::timing::summary(std::cerr);

    hilti::rt::done();

    if ( require_accept && (! accepted || declined) )
        return 1;

    return 0;
} catch ( const std::exception& e ) {
    SpicyDriver().fatalError(hilti::util::fmt("terminating with uncaught exception of type %s: %s",
                                              hilti::util::demangle(typeid(e).name()), e.what()));
}
