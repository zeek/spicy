// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
//
// Thin wrapper around the C++ compiler (MSVC cl.exe) that translates
// GCC/Clang-style flags so that the documented invocation
//
//   $(spicy-config --cxx) -o output source.cc $(spicy-config --cxxflags --ldflags)
//
// works identically on all platforms.
//
// Translations performed:
//   -o FILE  →  /Fe:FILE   (when linking)
//   -o FILE  →  /Fo:FILE   (when compiling with -c)
//
// After a successful link the wrapper also creates a copy of FILE from
// FILE.exe so that "./foo" works in MSYS2/Git-Bash where transparent
// .exe resolution is not always reliable.

#ifdef _WIN32

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include <process.h>
#include <windows.h>

// Path to the real C++ compiler, substituted by CMake.
#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)
static const char* real_cxx = STRINGIFY(HILTI_CXX_DRIVER_REAL_CXX);

int main(int argc, char* argv[]) {
    // First pass: detect compile-only mode (-c).
    bool compile_only = false;
    for ( int i = 1; i < argc; ++i ) {
        if ( std::strcmp(argv[i], "-c") == 0 ) {
            compile_only = true;
            break;
        }
    }

    std::vector<std::string> args;
    args.push_back(real_cxx);

    std::string output_name; // tracks the -o argument if present
    std::string output_flag; // the translated /Fe: or /Fo: flag

    for ( int i = 1; i < argc; ++i ) {
        if ( std::strcmp(argv[i], "-o") == 0 && i + 1 < argc ) {
            output_name = argv[++i];
            if ( compile_only )
                output_flag = "/Fo:" + output_name;
            else
                output_flag = "/Fe:" + output_name;
        }
        else {
            args.push_back(argv[i]);
        }
    }

    // On MSVC everything after -link (or /link) is forwarded to the
    // linker, so compiler-level items (output flag, source files) that
    // ended up after the separator must be moved in front of it.
    auto link_it = std::find(args.begin(), args.end(), "-link");
    if ( link_it == args.end() )
        link_it = std::find(args.begin(), args.end(), "/link");
    if ( link_it != args.end() ) {
        // Move source/object files from after /link to before it.
        for ( auto it = link_it + 1; it != args.end(); ) {
            const auto& a = *it;
            auto dot = a.rfind('.');
            if ( dot != std::string::npos ) {
                auto ext = a.substr(dot);
                if ( ext == ".cc" || ext == ".cpp" || ext == ".c" || ext == ".cxx" || ext == ".obj" || ext == ".o" ) {
                    auto val = std::move(*it);
                    it = args.erase(it);
                    link_it = args.insert(link_it, std::move(val)) + 1;
                    continue;
                }
            }
            ++it;
        }
    }

    if ( ! output_flag.empty() ) {
        // Re-find /link since iterators were invalidated above.
        auto it = std::find(args.begin(), args.end(), "-link");
        if ( it == args.end() )
            it = std::find(args.begin(), args.end(), "/link");
        args.insert(it != args.end() ? it : args.end(), output_flag);
    }

    // Build a C-style argv array for _spawnv.  On Windows _spawnv
    // concatenates the elements with spaces to form the command line,
    // so any element containing a space must be double-quoted.
    std::vector<std::string> quoted;
    quoted.reserve(args.size());
    for ( const auto& a : args ) {
        if ( a.find(' ') != std::string::npos )
            quoted.push_back("\"" + a + "\"");
        else
            quoted.push_back(a);
    }

    std::vector<const char*> cargs;
    cargs.reserve(quoted.size() + 1);
    for ( const auto& a : quoted )
        cargs.push_back(a.c_str());
    cargs.push_back(nullptr);

    auto rc = static_cast<int>(_spawnv(_P_WAIT, real_cxx, cargs.data()));

    // MSVC always produces FILE.exe even when /Fe:FILE is given.
    // Copy it so that ./foo works in bash.
    if ( rc == 0 && ! compile_only && ! output_name.empty() ) {
        auto exe = output_name + ".exe";
        CopyFileA(exe.c_str(), output_name.c_str(), /*bFailIfExists=*/FALSE);
    }

    return rc;
}

#else
#error "hilti-cxx-driver is only needed on Windows/MSVC"
#endif
