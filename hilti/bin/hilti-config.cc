// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
///
/// Outputs paths and flags for using HILTI.
///
/// TODO: Currently we do not support installation outside of the built-tree
/// and all values returned here are thus in-tree.

#include <iostream>
#include <list>
#include <sstream>
#include <string>

#include <hilti/autogen/config.h>
#include <hilti/base/util.h>
#include <hilti/compiler/jit.h>

using namespace std;

void usage() {
    std::cerr << R"(
Usage: hilti-config [options]

Available options:

    --build                 Prints "debug" or "release", depending on the build configuration.
    --cxx                   Print the full path to the compiler used to compile HILTI.
    --cxxflags              Print C++ flags when compiling code using the HILTI runtime library
    --debug                 Output flags for working with debugging versions.
    --distbase              Print path of the HILTI source distribution.
    --help                  Print this usage summary
    --hiltic                Print the full path to the hiltic binary.
    --jit-compiler          Prints the version of the JIT compiler if compiled with corresponding support.
    --jit-support           Prints 'yes' if compiled with JIT support, 'no' otherwise.
    --ldflags               Print linker flags when linking code using the HILTI runtime library
    --libdirs               Print standard HILTI library directories.
    --prefix                Print path of installation.
    --version               Print HILTI version.

    --using-build-dir       Returns true when hilti-config's output is referring to the build directory;
                            and false when refering to the installation
)";
}

template<typename U, typename V>
void join(std::vector<U>& a, const std::vector<V>& b) {
    a.insert(a.end(), b.begin(), b.end());
}

int main(int argc, char** argv) {
    bool want_debug = false;

    std::list<string> cxxflags;
    std::list<string> ldflags;

    std::list<string> options;

    // First pass over arguments: look for control options.

    for ( int i = 1; i < argc; i++ ) {
        string opt = argv[i];

        if ( opt == "--help" || opt == "-h" ) {
            usage();
            return 0;
        }

        if ( opt == "--debug" ) {
            want_debug = true;
            continue;
        }

        options.push_back(opt);
    }

    std::vector<std::string> result;

    for ( const auto& opt : options ) {
        if ( opt == "--distbase" ) {
            result.emplace_back(hilti::configuration().distbase);
            continue;
        }

        if ( opt == "--prefix" ) {
            result.emplace_back(hilti::configuration().install_prefix);
            continue;
        }

        if ( opt == "--version" ) {
            result.emplace_back(hilti::configuration().version_string_long);
            continue;
        }

        if ( opt == "--build" ) {
#ifndef NDEBUG
            result.emplace_back("debug");
#else
            result.emplace_back("release");
#endif
            continue;
        }

        if ( opt == "--jit-compiler" ) {
            result.emplace_back(hilti::JIT::compilerVersion());
            continue;
        }

        if ( opt == "--jit-support" ) {
            result.emplace_back((hilti::configuration().jit_enabled ? "yes" : "no"));
            continue;
        }

        if ( opt == "--cxx" ) {
            result.emplace_back(hilti::configuration().cxx);
            continue;
        }

        if ( opt == "--hiltic" ) {
            result.emplace_back(hilti::configuration().hiltic);
            continue;
        }

        if ( opt == "--libdirs" ) {
            join(result, hilti::configuration().hilti_library_paths);
            continue;
        }

        if ( opt == "--cxxflags" ) {
            if ( want_debug )
                join(result, hilti::configuration().runtime_cxx_flags_debug);
            else
                join(result, hilti::configuration().runtime_cxx_flags_release);

            continue;
        }

        if ( opt == "--ldflags" ) {
            if ( want_debug )
                join(result, hilti::configuration().runtime_ld_flags_debug);
            else
                join(result, hilti::configuration().runtime_ld_flags_release);

            continue;
        }

        if ( opt == "--using-build-dir" )
            exit(hilti::configuration().uses_build_directory ? 0 : 1);

        std::cerr << "hilti-config: unknown option " << opt << "; use --help to see list." << std::endl;
        return 1;
    }

    cout << hilti::util::join(result.begin(), result.end(), " ") << std::endl;

    return 0;
}
