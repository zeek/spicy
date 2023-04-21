// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

/**
 * Stripped down version of spicy-driver that includes just the pieces to
 * drive already compiled parsers at runtime (rather than first compiling
 * them itself). This can be compiled along with the C++ source code of those
 * parsers to yield an final executable.
 */

#include <getopt.h>

#include <fstream>
#include <iostream>

#include <hilti/rt/libhilti.h>

#include <spicy/rt/libspicy.h>

using spicy::rt::fmt;

static struct option long_driver_options[] = {{"abort-on-exceptions", required_argument, nullptr, 'A'},
                                              {"file", required_argument, nullptr, 'f'},
                                              {"batch-file", required_argument, nullptr, 'F'},
                                              {"help", no_argument, nullptr, 'h'},
                                              {"increment", required_argument, nullptr, 'i'},
                                              {"list-parsers", no_argument, nullptr, 'l'},
                                              {"parser", required_argument, nullptr, 'p'},
                                              {"show-backtraces", required_argument, nullptr, 'B'},
                                              {"report-resource-usage", no_argument, nullptr, 'U'},
                                              {"version", no_argument, nullptr, 'v'},
                                              {nullptr, 0, nullptr, 0}};

static void fatalError(const std::string& prog, const std::string& msg) {
    fprintf(stderr, "[error] %s: %s\n", prog.c_str(), msg.c_str());
    spicy::rt::done();
    hilti::rt::done();
    exit(1);
}

class SpicyDriver : public spicy::rt::Driver {
public:
    SpicyDriver() = default;

    void parseOptions(const std::string& prog, int argc, char** argv);
    void usage(const std::string& prog);

    bool opt_abort_on_exceptions = false;
    bool opt_input_is_batch = false;
    bool opt_list_parsers = false;
    bool opt_report_resource_usage = false;
    bool opt_show_backtraces = false;
    int opt_increment = 0;
    std::string opt_file = "/dev/stdin";
    std::string opt_parser;
};

void SpicyDriver::usage(const std::string& prog) {
    std::cerr
        << "Usage: cat <data> | " << prog
        << " [options]\n"
           "\n"
           "Options:\n"
           "\n"
           "  -f | --file <path>              Read input from <path> instead of stdin.\n"
           "  -i | --increment <i>            Feed data incrementenally in chunks of size n.\n"
           "  -l | --list-parsers             List available parsers and exit.\n"
           "  -p | --parser <name>            Use parser <name> to process input. Only needed if more than one parser "
           "is available.\n"
           "  -v | --version                  Print version information.\n"
           "  -A | --abort-on-exceptions      When executing compiled code, abort() instead of throwing HILTI "
           "exceptions.\n"
           "  -B | --show-backtraces          Include backtraces when reporting unhandled exceptions.\n"
           "  -F | --batch-file <path>        Read Spicy batch input from <path>; see docs for description of format.\n"
           "  -U | --report-resource-usage    Print summary of runtime resource usage.\n"
           "\n";
}

void SpicyDriver::parseOptions(const std::string& prog, int argc, char** argv) {
    while ( true ) {
        int c = getopt_long(argc, argv, "ABF:hdf:lp:i:vU", long_driver_options, nullptr);

        if ( c < 0 )
            break;

        switch ( c ) {
            case 'A': opt_abort_on_exceptions = true; break;
            case 'B': opt_show_backtraces = true; break;
            case 'F': {
                opt_file = optarg;
                opt_input_is_batch = true;
                break;
            }
            case 'f': {
                opt_file = optarg;
                break;
            }
            case 'i':
                opt_increment = atoi(optarg); /* NOLINT */
                break;
            case 'l': opt_list_parsers = true; break;
            case 'p': opt_parser = optarg; break;
            case 'v': std::cerr << "spicy-driver v" << hilti::rt::version() << std::endl; exit(0);
            case 'U': opt_report_resource_usage = true; break;

            case 'h': usage(prog); exit(0);
            case '?': usage(prog); exit(1); // getopt reports error
            default: usage(prog); fatalError(prog, fmt("option %c not supported", c));
        }
    }

    if ( optind != argc )
        usage(prog);
}

int main(int argc, char** argv) {
    SpicyDriver driver;

    auto prog = hilti::rt::filesystem::path(argv[0]).filename().native();
    driver.parseOptions(prog, argc, argv);

    auto config = hilti::rt::configuration::get();
    config.abort_on_exceptions = driver.opt_abort_on_exceptions;
    config.show_backtraces = driver.opt_show_backtraces;
    config.report_resource_usage = driver.opt_report_resource_usage;
    hilti::rt::configuration::set(config);

    try {
        hilti::rt::init();
        spicy::rt::init();

        if ( driver.opt_list_parsers )
            driver.listParsers(std::cout);

        else {
            std::ifstream in(driver.opt_file, std::ios::in | std::ios::binary);

            if ( ! in.is_open() )
                fatalError(prog, "cannot open input for reading");

            if ( driver.opt_input_is_batch ) {
                if ( auto x = driver.processPreBatchedInput(in); ! x )
                    fatalError(prog, x.error());
            }
            else {
                auto parser = driver.lookupParser(driver.opt_parser);
                if ( ! parser )
                    fatalError(prog, parser.error());

                driver.processInput(**parser, in, driver.opt_increment);
            }
        }

        spicy::rt::done();
        hilti::rt::done();

    } catch ( const std::exception& e ) {
        fatalError(prog, hilti::rt::fmt("terminating with uncaught exception of type %s: %s",
                                        hilti::rt::demangle(typeid(e).name()), e.what()));
    }
}
