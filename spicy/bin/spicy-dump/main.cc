// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <getopt.h>
#include <iostream>

#include <hilti/hilti.h>
#include <spicy/spicy.h>

#include <hilti/rt/libhilti.h>
#include <spicy/rt/libspicy.h>

#include "options.h"
#include "printer-json.h"
#include "printer-text.h"

using spicy::rt::fmt;

static struct option long_options[] = {{"abort-on-exceptions", required_argument, nullptr, 'A'},
                                       {"compiler-debug", required_argument, nullptr, 'D'},
                                       {"debug", no_argument, nullptr, 'd'},
                                       {"debug-addl", required_argument, nullptr, 'X'},
                                       {"enable-print", no_argument, nullptr, 'P'},
                                       {"file", required_argument, nullptr, 'f'},
                                       {"help", no_argument, nullptr, 'h'},
                                       {"json", no_argument, nullptr, 'J'},
                                       {"library-path", required_argument, nullptr, 'L'},
                                       {"list-parsers", no_argument, nullptr, 'l'},
                                       {"optimize", no_argument, nullptr, 'O'},
                                       {"parser", required_argument, nullptr, 'p'},
                                       {"report-times", required_argument, nullptr, 'R'},
                                       {"show-backtraces", required_argument, nullptr, 'B'},
                                       {"skip-dependencies", no_argument, nullptr, 'S'},
                                       {"version", no_argument, nullptr, 'v'},
                                       {nullptr, 0, nullptr, 0}};

static void fatalError(const std::string& msg) {
    hilti::logger().error(fmt("spicy-dump: %s", msg));
    exit(1);
}

class SpicyDump : public hilti::Driver, public spicy::rt::Driver {
public:
    SpicyDump(const std::string_view& argv0 = "") : hilti::Driver("spicy-dump", argv0) {
        spicy::Configuration::extendHiltiConfiguration();
    }

    void parseOptions(int argc, char** argv);
    void usage();

    bool opt_json = false;
    bool opt_list_parsers = false;
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
           "  -l | --list-parsers             List available parsers and exit.\n"
           "  -p | --parser <name>            Use parser <name> to process input. Only neeeded if more than one parser "
           "is available.\n"
           "  -v | --version                  Print version information.\n"
           "  -A | --abort-on-exceptions      When executing compiled code, abort() instead of throwing HILTI "
           "exceptions.\n"
           "  -B | --show-backtraces          Include backtraces when reporting unhandled exceptions.\n"
           "  -D | --compiler-debug <streams> Activate compile-time debugging output for given debug streams "
           "(comma-separated; 'help' for list).\n"
           "  -L | --library-path <path>      Add path to list of directories to search when importing modules.\n"
           "  -J | --json                     Print JSON output.\n"
           "  -O | --optimize                 Build optimized release version of generated code.\n"
           "  -P | --enable-print             Show output of Spicy 'print' statements (default: off).\n"
           "  -R | --report-times             Report a break-down of compiler's execution time.\n"
           "  -S | --skip-dependencies        Do not automatically compile dependencies during JIT.\n"
           "  -X | --debug-addl <addl>        Implies -d and adds selected additional instrumentation "
           "(comma-separated; see 'help' for list).\n"
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

/** TODO: Can we factor out common option handling to the Spicy driver? */
void SpicyDump::parseOptions(int argc, char** argv) {
    hilti::driver::Options driver_options;
    hilti::Options compiler_options;

    driver_options.execute_code = true;
    driver_options.include_linker = true;
    driver_options.logger = std::make_unique<hilti::Logger>();

    while ( true ) {
        int c = getopt_long(argc, argv, "ABD:f:hdX:OVlp:PSRL:J", long_options, nullptr);

        if ( c < 0 )
            break;

        switch ( c ) {
            case 'A': driver_options.abort_on_exceptions = true; break;

            case 'B': driver_options.show_backtraces = true; break;

            case 'd': {
                compiler_options.debug = true;
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

                compiler_options.debug = true;

                if ( auto r = compiler_options.parseDebugAddl(arg); ! r )
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

            case 'l': opt_list_parsers = true; break;

            case 'p': opt_parser = optarg; break;

            case 'P': opt_enable_print = true; break;

            case 'O': compiler_options.optimize = true; break;

            case 'R': driver_options.report_times = true; break;

            case 'S': driver_options.skip_dependencies = true; break;

            case 'v': std::cerr << "spicy-dump v" << hilti::configuration().version_string_long << std::endl; exit(0);

            case 'h': usage(); exit(0);

            case 'L': compiler_options.library_paths.emplace_back(optarg); break;

            default: usage(); fatalError(fmt("option %c not supported", c));
        }
    }

    setCompilerOptions(compiler_options);
    setDriverOptions(std::move(driver_options));

    initialize();

    while ( optind < argc ) {
        if ( auto rc = addInput(argv[optind++]); ! rc )
            fatalError(rc.error().description());
    }
}

int main(int argc, char** argv) {
    SpicyDump driver;

    driver.parseOptions(argc, argv);

    if ( auto x = driver.compile(); ! x )
        // The main error messages have been reported already at this point.
        // The returned error will have some more info about which pass
        // failed in its description, however that's less interesting to the
        // user so we're just reporting a generic message here.
        fatalError("aborting after errors");

    try {
        auto config = hilti::rt::configuration::get();
        config.cout.reset();
        hilti::rt::configuration::set(config);

        if ( auto x = driver.initRuntime(); ! x )
            fatalError(x.error().description());

        if ( driver.opt_list_parsers )
            driver.listParsers(std::cout);

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
            else
                TextPrinter(std::cout, driver.output_options).print(unit->value());

            driver.finishRuntime();
        }

    } catch ( const std::exception& e ) {
        std::cerr << hilti::util::fmt("[fatal error] terminating with uncaught exception of type %s: %s",
                                      hilti::util::demangle(typeid(e).name()), e.what())
                  << std::endl;
        exit(1);
    }

    return 0;
}
