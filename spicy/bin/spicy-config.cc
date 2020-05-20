// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.
//
// Outputs paths and flags for using Spicy.

#include <iostream>
#include <list>
#include <sstream>
#include <string>

#include <hilti/base/util.h>
#include <hilti/compiler/jit.h>

#include <hilti/autogen/config.h>
#include <spicy/autogen/config.h>

using namespace std;

void usage() {
    std::cerr << R"(
Usage: spicy-config [options]

Available options:

    --build                 Prints "debug" or "release", depending on the build configuration.
    --bindir                Prints the path to the directory where binaries are installed.
    --cxx                   Print the path to the C++ compiler used to build Spicy
    --cxxflags              Print flags for C++ compiler. (These are addition to any that HILTI needs.)
    --debug                 Output flags for working with debugging versions.
    --distbase              Print path of the Spicy source distribution.
    --help                  Print this usage summary
    --jit-compiler          Prints the version of the JIT compiler if compiled with corresponding support.
    --jit-support           Prints 'yes' if compiled with JIT support, 'no' otherwise.
    --ldflags               Print flags for linker. (These are addition to any that HILTI needs.)
    --libdirs               Print standard Spicy library directories.
    --prefix                Print path of installation (TODO: same as --distbase currently)
    --spicy-build           Print the path to the spicy-build script.
    --spicyc                Print the path to the spicyc binary.
    --zeek                  Print the path to the Zeek executable
    --zeek-prefix           Print the path to the Zeek installation prefix
    --zeek-plugin-path      Print the path to go into ZEEK_PLUGIN_PATH for enabling the Zeek Spicy plugin
    --zeek-jit-support      Prints 'yes' if the Zeek plugin was compiled with JIT support, 'no' otherwise.
    --version               Print Spicy version.

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

    spicy::configuration().extendHiltiConfiguration();

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

        if ( opt == "--bindir" ) {
            result.emplace_back(spicy::configuration().spicyc.parent_path());
            continue;
        }

        if ( opt == "--jit-compiler" ) {
            result.emplace_back(hilti::JIT::compilerVersion());
            continue;
        }

        if ( opt == "--jit-support" ) {
            result.emplace_back(hilti::configuration().jit_enabled ? "yes" : "no");
            continue;
        }

        if ( opt == "--cxx" ) {
            result.emplace_back(hilti::configuration().cxx);
            continue;
        }

        if ( opt == "--spicyc" ) {
            result.emplace_back(spicy::configuration().spicyc);
            continue;
        }

        if ( opt == "--spicy-build" ) {
            result.emplace_back((spicy::configuration().spicyc.parent_path() / "spicy-build"));
            continue;
        }

        if ( opt == "--zeek" ) {
#ifdef HAVE_ZEEK
            result.emplace_back(ZEEK_EXECUTABLE);
            continue;
#else
            exit(1);
#endif
        }

        if ( opt == "--zeek-prefix" ) {
#ifdef HAVE_ZEEK
            result.emplace_back(ZEEK_PREFIX);
            continue;
#else
            exit(1);
#endif
        }

        if ( opt == "--zeek-plugin-path" ) {
#ifdef HAVE_ZEEK
            if ( hilti::configuration().uses_build_directory )
                result.emplace_back(hilti::configuration().build_directory / "zeek/plugin");
            else
                result.emplace_back(hilti::configuration().lib_directory / "spicy/Zeek_Spicy");

            continue;
#else
            exit(1);
#endif
        }

        if ( opt == "--zeek-jit-support" ) {
#ifdef HAVE_ZEEK
#ifdef ZEEK_HAVE_JIT
            result.emplace_back("yes");
#else
            result.emplace_back("no");
#endif
            continue;
#else
            exit(1);
#endif
        }

        if ( opt == "--libdirs" ) {
            join(result, spicy::configuration().spicy_library_paths);
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

        std::cerr << "spicy-config: unknown option " << opt << "; use --help to see list." << std::endl;
        return 1;
    }

    cout << util::join(result.begin(), result.end(), " ") << std::endl;

    return 0;
}
