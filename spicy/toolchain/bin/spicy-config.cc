// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
//
// Outputs paths and flags for using Spicy.

#include <exception>
#include <iostream>
#include <list>
#include <string>

#include <hilti/autogen/config.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>

#include <spicy/autogen/config.h>

using namespace std;

static void usage() {
    std::cout << R"(
Usage: spicy-config [options]

Available options:

    --bindir                 Prints the path to the directory where binaries are installed.
    --build                  Prints "debug" or "release", depending on the build configuration.
    --cmake-path             Prints the path to Spicy-provided CMake modules
    --cxx                    Print the path to the C++ compiler used to build Spicy
    --cxx-launcher           Print the full path to the compiler launcher used to compile HILTI.
    --cxxflags               Print flags for C++ compiler when compiling generated code statically
    --cxxflags-hlto          Print flags for C++ compiler when building precompiled HLTO libraries
    --debug                  Output flags for working with debugging versions.
    --distbase               Print path of the Spicy source distribution.
    --dynamic-loading        Adjust --ldflags for host applications that dynamically load precompiled modules
    --have-toolchain         Prints 'yes' if the Spicy toolchain was built, 'no' otherwise.
    --help                   Print this usage summary
    --include-dirs           Prints the Spicy runtime's C++ include directories
    --include-dirs-toolchain Prints the Spicy compiler's C++ include directories
    --ldflags                Print flags for linker when compiling generated code statically
    --ldflags-hlto           Print flags for linker linker when building precompiled HLTO libraries
    --libdirs                Print standard Spicy library directories.
    --libdirs-cxx-runtime    Print C++ library directories for runtime.
    --libdirs-cxx-toolchain  Print C++ library directories for toolchain.
    --prefix                 Print path of installation
    --spicy-build            Print the path to the spicy-build script.
    --spicyc                 Print the path to the spicyc binary.
    --version                Print the Spicy version as a string.
    --version-number         Print the Spicy version as a numerical value.

)";
}

template<typename U, typename V>
static void join(std::vector<U>& a, const std::vector<V>& b) {
    a.insert(a.end(), b.begin(), b.end());
}

int main(int argc, char** argv) try {
    bool want_debug = false;
    bool want_dynamic_linking = false;

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

        if ( opt == "--dynamic-loading" ) {
            want_dynamic_linking = true;
            continue;
        }

        options.push_back(std::move(opt));
    }

    hilti::configuration().initLocation(hilti::util::currentExecutable());
    spicy::Configuration::extendHiltiConfiguration();

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

        if ( opt == "--version-number" ) {
            result.emplace_back(std::to_string(hilti::configuration().version_number));
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

        if ( opt == "--have-toolchain" ) {
#ifdef HAVE_TOOLCHAIN
            result.emplace_back("yes");
#else
            result.emplace_back("no");
#endif
            continue;
        }

        if ( opt == "--cxx" ) {
            result.emplace_back(hilti::configuration().cxx);
            continue;
        }

        if ( opt == "--cxx-launcher" ) {
            if ( auto cxx_launcher = hilti::configuration().cxx_launcher )
                result.emplace_back(*cxx_launcher);

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

        if ( opt == "--cmake-path" ) {
            if ( hilti::configuration().uses_build_directory )
                result.emplace_back(hilti::configuration().distbase / "cmake");
            else
                result.emplace_back(hilti::configuration().install_prefix / "share/spicy/cmake");

            continue;
        }

        if ( opt == "--libdirs" ) {
            join(result, spicy::configuration().spicy_library_paths);
            continue;
        }

        if ( opt == "--libdirs-cxx-runtime" ) {
            join(result, hilti::configuration().runtime_cxx_library_paths);
            continue;
        }

        if ( opt == "--libdirs-cxx-toolchain" ) {
            join(result, hilti::configuration().toolchain_cxx_library_paths);
            continue;
        }

        if ( opt == "--include-dirs" ) {
            join(result, hilti::configuration().runtime_cxx_include_paths);
            continue;
        }

        if ( opt == "--include-dirs-toolchain" ) {
            join(result, hilti::configuration().toolchain_cxx_include_paths);
            continue;
        }

        if ( opt == "--cxxflags" ) {
            if ( want_debug )
                join(result, hilti::configuration().runtime_cxx_flags_debug);
            else
                join(result, hilti::configuration().runtime_cxx_flags_release);

            continue;
        }

        if ( opt == "--cxxflags-hlto" ) {
            if ( want_debug )
                join(result, hilti::configuration().hlto_cxx_flags_debug);
            else
                join(result, hilti::configuration().hlto_cxx_flags_release);

            continue;
        }

        if ( opt == "--ldflags" ) {
            if ( want_dynamic_linking ) {
#if __APPLE__
                result.emplace_back("-Wl,-all_load");
#else
                result.emplace_back("-Wl,--export-dynamic");
                result.emplace_back("-Wl,--whole-archive");
#endif
            }

            if ( want_debug )
                join(result, hilti::configuration().runtime_ld_flags_debug);
            else
                join(result, hilti::configuration().runtime_ld_flags_release);

            if ( want_dynamic_linking ) {
#if ! (__APPLE__)
                result.emplace_back("-Wl,--no-whole-archive");
#endif
            }

            continue;
        }

        if ( opt == "--ldflags-hlto" ) {
            if ( want_debug )
                join(result, hilti::configuration().hlto_ld_flags_debug);
            else
                join(result, hilti::configuration().hlto_ld_flags_release);

            continue;
        }

        std::cerr << "spicy-config: unknown option " << opt << "; use --help to see list." << '\n';
        return 1;
    }

    cout << hilti::util::join(result, " ") << '\n';

    return 0;
} catch ( const std::exception& e ) {
    hilti::logger().fatalError(hilti::util::fmt("terminating with uncaught exception of type %s: %s",
                                                hilti::util::demangle(typeid(e).name()), e.what()));
}
