// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <getopt.h>

#include <fstream>
#include <iostream>

#include <hilti/rt/libhilti.h>

#include <spicy/rt/libspicy.h>

#include <hilti/hilti.h>

#include <spicy/spicy.h>

using spicy::rt::fmt;

static struct option long_driver_options[] = {{"abort-on-exceptions", required_argument, nullptr, 'A'},
                                              {"compiler-debug", required_argument, nullptr, 'D'},
                                              {"debug", no_argument, nullptr, 'd'},
                                              {"debug-addl", required_argument, nullptr, 'X'},
                                              {"file", required_argument, nullptr, 'f'},
                                              {"batch-file", required_argument, nullptr, 'F'},
                                              {"help", no_argument, nullptr, 'h'},
                                              {"increment", required_argument, nullptr, 'i'},
                                              {"library-path", required_argument, nullptr, 'L'},
                                              {"list-parsers", no_argument, nullptr, 'l'},
                                              {"optimize", no_argument, nullptr, 'O'},
                                              {"parser", required_argument, nullptr, 'p'},
                                              {"report-times", required_argument, nullptr, 'R'},
                                              {"show-backtraces", required_argument, nullptr, 'B'},
                                              {"skip-dependencies", no_argument, nullptr, 'S'},
                                              {"report-resource-usage", no_argument, nullptr, 'U'},
                                              {"version", no_argument, nullptr, 'v'},
                                              {nullptr, 0, nullptr, 0}};

static void fatalError(const std::string& msg) {
    hilti::logger().error(msg);
    spicy::rt::done();
    hilti::rt::done();
    exit(1);
}

static void fatalError(const hilti::result::Error& error) {
    hilti::logger().error(error.description());

    if ( error.context().size() )
        hilti::logger().error(error.context());

    spicy::rt::done();
    hilti::rt::done();
    exit(1);
}

class SpicyDriver : public spicy::Driver, public spicy::rt::Driver {
public:
    SpicyDriver(const std::string_view& argv0 = "") : spicy::Driver("spicy-driver", argv0) {
        spicy::Configuration::extendHiltiConfiguration();
    }

    void parseOptions(int argc, char** argv);
    void usage();

    bool opt_list_parsers = false;
    int opt_increment = 0;
    bool opt_input_is_batch = false;
    std::string opt_file = "/dev/stdin";
    std::string opt_parser;

private:
    void hookInitRuntime() override { spicy::rt::init(); }
    void hookFinishRuntime() override { spicy::rt::done(); }
};

void SpicyDriver::usage() {
    auto exts = hilti::util::join(hilti::plugin::registry().supportedExtensions(), ", ");

    std::cerr
        << "Usage: cat <data> | spicy-driver [options] <inputs> ...\n"
           "\n"
           "Options:\n"
           "\n"
           "  -d | --debug                    Include debug instrumentation into generated code.\n"
           "  -i | --increment <i>            Feed data incrementally in chunks of size n.\n"
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
           "  -F | --batch-file <path>        Read Spicy batch input from <path>; see docs for description of "
           "format.\n"
           "  -L | --library-path <path>      Add path to list of directories to search when importing modules.\n"
           "  -O | --optimize                 Build optimized release version of generated code.\n"
           "  -R | --report-times             Report a break-down of compiler's execution time.\n"
           "  -S | --skip-dependencies        Do not automatically compile dependencies during JIT.\n"
           "  -U | --report-resource-usage    Print summary of runtime resource usage.\n"
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
        int c = getopt_long(argc, argv, "ABD:f:F:hdJX:OVlp:i:SRL:U", long_driver_options, nullptr);

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

            case 'F': {
                opt_file = optarg;
                opt_input_is_batch = true;
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

            case 'J': {
                driver_options.execute_code = false;
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

            case 'i':
                opt_increment = atoi(optarg); // NOLINT
                break;

            case 'l': opt_list_parsers = true; break;

            case 'p': opt_parser = optarg; break;

            case 'O': compiler_options.optimize = true; break;

            case 'R': driver_options.report_times = true; break;

            case 'S': driver_options.skip_dependencies = true; break;

            case 'U': driver_options.report_resource_usage = true; break;

            case 'v': std::cerr << "spicy-driver v" << hilti::configuration().version_string_long << std::endl; exit(0);

            case 'L': compiler_options.library_paths.emplace_back(optarg); break;

            case 'h': usage(); exit(0);
            case '?': usage(); exit(1); // getopt reports error
            default: usage(); fatalError(fmt("option %c not supported", c));
        }
    }

    setCompilerOptions(compiler_options);
    setDriverOptions(std::move(driver_options));

    initialize();

    while ( optind < argc ) {
        if ( auto rc = addInput(argv[optind++]); ! rc )
            fatalError(rc.error());
    }
}

int main(int argc, char** argv) {
    SpicyDriver driver;

    driver.parseOptions(argc, argv);

    if ( auto x = driver.compile(); ! x ) {
        fatalError(x.error());
    }

    try {
        if ( auto x = driver.initRuntime(); ! x )
            fatalError(x.error());

        if ( driver.opt_list_parsers )
            driver.listParsers(std::cout);

        else {
            std::ifstream in(driver.opt_file, std::ios::in | std::ios::binary);

            if ( ! in.is_open() )
                fatalError("cannot open input for reading");

            if ( driver.opt_input_is_batch ) {
                if ( auto x = driver.processPreBatchedInput(in); ! x )
                    fatalError(x.error());
            }
            else {
                auto parser = driver.lookupParser(driver.opt_parser);
                if ( ! parser )
                    fatalError(parser.error());

                driver.processInput(**parser, in, driver.opt_increment);
            }
        }

        driver.finishRuntime();

    } catch ( const std::exception& e ) {
        fatalError(hilti::util::fmt("terminating with uncaught exception of type %s: %s",
                                    hilti::util::demangle(typeid(e).name()), e.what()));
    }

    if ( driver.driverOptions().report_times )
        hilti::util::timing::summary(std::cerr);

    hilti::rt::done();

    return 0;
}
