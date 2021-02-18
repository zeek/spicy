// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.
//
// Outputs paths and flags for using Spicy.

#include <iostream>
#include <list>
#include <sstream>
#include <string>

#include <hilti/autogen/config.h>
#include <hilti/base/util.h>

#include <spicy/autogen/config.h>

using namespace std;

void usage() {
    std::cerr << R"(
Usage: spicy-config [options]

Available options:

    --build                 Prints "debug" or "release", depending on the build configuration.
    --bindir                Prints the path to the directory where binaries are installed.
    --cmake-path            Prints the path to Spicy-provided CMake modules
    --cxx                   Print the path to the C++ compiler used to build Spicy
    --cxxflags              Print flags for C++ compiler when compiling generated code statically
    --cxxflags-hlto         Print flags for C++ compiler when building precompiled HLTO libraries
    --debug                 Output flags for working with debugging versions.
    --distbase              Print path of the Spicy source distribution.
    --dynamic-loading       Adjust --ldflags for host applications that dynamically load precompiled modules
    --help                  Print this usage summary
    --include-dirs          Prints the Spicy runtime's C++ include directories
    --ldflags               Print flags for linker when compiling generated code statically
    --ldflags-hlto          Print flags for linker linker when building precompiled HLTO libraries
    --libdirs               Print standard Spicy library directories.
    --prefix                Print path of installation (TODO: same as --distbase currently)
    --spicy-build           Print the path to the spicy-build script.
    --spicyc                Print the path to the spicyc binary.
    --toolchain             Prints 'yes' if the Spicy toolchain was built, 'no' otherwise.
    --version               Print the Spicy version as a string.
    --version-number        Print the Spicy version as a numerical value.
    --zeek                  Print the path to the Zeek executable
    --zeek-include-dirs     Print the Spicy runtime's C++ include directories
    --zeek-prefix           Print the path to the Zeek installation prefix
    --zeek-plugin-path      Print the path to go into ZEEK_PLUGIN_PATH for enabling the Zeek Spicy plugin
    --zeek-version-number   Print the Zeek version as a numerical value (zero if no Zeek available)

)";
}

template<typename U, typename V>
void join(std::vector<U>& a, const std::vector<V>& b) {
    a.insert(a.end(), b.begin(), b.end());
}

int main(int argc, char** argv) {
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

        if ( opt == "--toolchain" ) {
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
#ifdef HAVE_ZEEK_PLUGIN
            if ( hilti::configuration().uses_build_directory )
                result.emplace_back(hilti::configuration().build_directory / "zeek/plugin");
            else
                result.emplace_back(hilti::configuration().lib_directory / "spicy/Zeek_Spicy");

            continue;
#else
            exit(1);
#endif
        }

        if ( opt == "--zeek-include-dirs" ) {
#ifdef HAVE_ZEEK_PLUGIN
            if ( hilti::configuration().uses_build_directory ) {
                result.emplace_back(hilti::configuration().distbase / "zeek/plugin/include");
                result.emplace_back(hilti::configuration().build_directory / "zeek/plugin");
            }
            else
                result.emplace_back(hilti::configuration().install_prefix / "include");

            continue;
#else
            exit(1);
#endif
        }

        if ( opt == "--zeek-version" || opt == "--zeek-version-number" ) {
            // Renamed to --zeek-version-number, but accept old name for backwards compatibility.
#ifdef HAVE_ZEEK
            result.emplace_back(ZEEK_VERSION_NUMBER_STRING);
#else
            result.emplace_back("0");
#endif
            continue;
        }

        if ( opt == "--libdirs" ) {
            join(result, spicy::configuration().spicy_library_paths);
            continue;
        }

        if ( opt == "--include-dirs" ) {
            std::set<std::string> paths;

            for ( auto i : hilti::configuration().hilti_include_paths )
                paths.insert(i);

            for ( auto i : spicy::configuration().spicy_include_paths )
                paths.insert(i);

            join(result, hilti::util::transform_to_vector(paths, [](auto x) { return x; }));
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
                result.push_back("-Wl,-all_load");
#else
                result.push_back("-Wl,--export-dynamic");
                result.push_back("-Wl,--whole-archive");
#endif
            }

            if ( want_debug )
                join(result, hilti::configuration().runtime_ld_flags_debug);
            else
                join(result, hilti::configuration().runtime_ld_flags_release);

            if ( want_dynamic_linking ) {
#if __APPLE__
                result.push_back("-Wl,-noall_load");
#else
                result.push_back("-Wl,--no-whole-archive");
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

        std::cerr << "spicy-config: unknown option " << opt << "; use --help to see list." << std::endl;
        return 1;
    }

    cout << hilti::util::join(result.begin(), result.end(), " ") << std::endl;

    return 0;
}
