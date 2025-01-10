// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
///
/// Implementation of main() which directly executes Main::run().
///

#include <getopt.h>

#include <exception>
#include <iostream>

#include <hilti/rt/libhilti.h>

static struct option long_options[] = {{nullptr, 0, nullptr, 0}};

static void usage(const char* prog) {
    std::cerr << hilti::rt::
            fmt("%s: HILTI runtime environment - "
                "executing only global code; no command-line argument handling or other processing\n",
                prog);
}

namespace hilti {
// NOLINTNEXTLINE(misc-use-internal-linkage)
int main(int argc, char** argv);
} // namespace hilti

// Top-level entry point generated by HILTI compiler. We declare our
// implementation weak so any external implementation will override it.
int HILTI_WEAK hilti::main(int argc, char** argv) {
    const auto& config = hilti::rt::configuration::get();

    while ( true ) {
        int c = getopt_long(argc, argv, "h", long_options, nullptr);

        if ( c == -1 )
            break;

        switch ( c ) { // NOLINT
            case 'h': usage(argv[0]); break;
            case '?': usage(argv[0]); exit(1);
            default: usage(argv[0]); exit(1);
        }
    }

    if ( optind != argc )
        usage(argv[0]);

    hilti::rt::configuration::set(config);
    hilti::rt::init();
    hilti::rt::done();

    return 0;
}

int HILTI_WEAK main(int argc, char** argv) try { return hilti::main(argc, argv); } catch ( const std::exception& e ) {
    hilti::rt::fatalError(hilti::rt::fmt("terminating with uncaught exception of type %s: %s",
                                         hilti::rt::demangle(typeid(e).name()), e.what()));
}
