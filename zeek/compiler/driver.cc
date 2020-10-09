// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include "driver.h"

#include <getopt.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/declarations/type.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit.h>
#include <spicy/autogen/config.h>

#include "debug.h"
#include "glue-compiler.h"

// Must come after Bro includes to avoid namespace conflicts.
#include <spicy/rt/libspicy.h>

using namespace spicy::zeek;
using Driver = spicy::zeek::Driver;

/** Visitor to extract unit information from an HILTI AST before it's compiled. */
struct VisitorPreCompilation : public hilti::visitor::PreOrder<void, VisitorPreCompilation> {
    explicit VisitorPreCompilation(Driver* driver, hilti::ID module, hilti::rt::filesystem::path path)
        : driver(driver), module(std::move(module)), path(std::move(path)) {}

    void operator()(const hilti::declaration::Type& t) {
        if ( auto et = t.type().tryAs<hilti::type::Enum>(); et && t.linkage() == hilti::declaration::Linkage::Public ) {
            auto ei = EnumInfo{
                .id = hilti::ID(module, t.id()),
                .type = *et,
                .module_id = module,
                .module_path = path,
            };

            enums.emplace_back(std::move(ei));
        }
    }

    Driver* driver;
    hilti::ID module;
    hilti::rt::filesystem::path path;
    std::vector<EnumInfo> enums;
};

/** Visitor to extract unit information from an HILTI AST after it's compiled. */
struct VisitorPostCompilation : public hilti::visitor::PreOrder<void, VisitorPostCompilation> {
    explicit VisitorPostCompilation(Driver* driver, hilti::ID module, hilti::rt::filesystem::path path)
        : driver(driver), module(std::move(module)), path(std::move(path)) {}

    void operator()(const hilti::declaration::Type& t) {
        if ( const auto& orig = t.type().originalNode() ) {
            if ( auto ut = orig->tryAs<spicy::type::Unit>() ) {
                auto ui = UnitInfo{
                    .id = *t.type().typeID(),
                    .type = *ut,
                    .module_id = module,
                    .module_path = path,
                };

                units.emplace_back(std::move(ui));
            }
        }
    }

    Driver* driver;
    hilti::ID module;
    hilti::rt::filesystem::path path;
    std::vector<UnitInfo> units;
};

Driver::Driver(const std::string& argv0, int zeek_version) : spicy::Driver("<Spicy Plugin for Zeek>") {
    if ( argv0.size() )
        hilti::configuration().initLocation(argv0);

    spicy::Configuration::extendHiltiConfiguration();
    _glue = std::make_unique<GlueCompiler>(this, zeek_version);
}

Driver::~Driver() {}

void Driver::usage(std::ostream& out) {
    out << "\nSupported Zeek-side Spicy options:\n"
           "\n"
           "  -d             Include debug instrumentation into generated code.\n"
           "  -o <out.hlto>  Save precompiled code into file and exit.\n"
           "  -A             When executing compiled code, abort() instead of throwing HILTI exceptions.\n"
           "  -B             Include backtraces when reporting unhandled exceptions.\n"
           "  -C             Dump all generated code to disk for debugging.\n"
           "  -D <streams>   Activate compile-time debugging output for given debug streams (comma-separated).\n"
           "  -L <path>      Add path to list of directories to search when importing modules.\n"
           "  -O             Build optimized release version of generated code.\n"
           "  -R             Report a break-down of compiler's execution time.\n"
           "  -V             Don't validate ASTs (for debugging only).\n"
           "  -X <addl>      Implies -d and adds selected additional instrumentation (comma-separated).\n"
           "\n";
}

hilti::Result<hilti::Nothing> Driver::parseOptionsPreScript(const std::string& options) {
    auto args = hilti::util::filter(hilti::util::transform(hilti::util::split(options),
                                                           [](auto o) { return hilti::util::trim(o); }),
                                    [](auto o) { return o.size(); });

    auto idx = 0;
    auto argc = args.size();
    while ( idx < argc ) {
        if ( args[idx][0] != '-' ) {
            idx++;
            continue;
        }

        if ( args[idx].size() != 2 )
            return hilti::result::Error("long options no supported");

        switch ( args[idx++][1] ) {
            case 'D': {
                if ( idx >= argc )
                    return hilti::result::Error("argument missing");

                auto optarg = args[idx++];
                for ( const auto& s : hilti::util::split(optarg, ",") ) {
                    if ( ! ::hilti::logger().debugEnable(s) )
                        return hilti::result::Error(hilti::util::fmt("unknown debug stream '%s'", s));
                }
                break;
            }

            case 'h': usage(std::cerr); exit(0);

            default:
                //  Error handling is left to parseOptionsPostScript().
                idx++;
                continue;
        }
    }

    return hilti::Nothing();
}

hilti::Result<hilti::Nothing> Driver::parseOptionsPostScript(const std::string& options,
                                                             hilti::driver::Options* driver_options,
                                                             hilti::Options* compiler_options) {
    // We do our own options parsing here (instead of using getopt()) so that
    // we don't interfere with anything Zeek-side.
    auto args = hilti::util::filter(hilti::util::transform(hilti::util::split(options),
                                                           [](auto o) { return hilti::util::trim(o); }),
                                    [](auto o) { return o.size(); });

    auto idx = 0;
    auto argc = args.size();
    while ( idx < argc ) {
        if ( args[idx][0] != '-' ) {
            driver_options->inputs.push_back(args[idx++]);
            continue;
        }

        if ( args[idx].size() != 2 )
            return hilti::result::Error("long options no supported");

        char c = args[idx++][1];
        switch ( c ) {
            case 'A': driver_options->abort_on_exceptions = true; break;

            case 'B': driver_options->show_backtraces = true; break;

            case 'd': compiler_options->debug = true; break;

            case 'C': driver_options->dump_code = true; break;

            case 'D':
                idx++; // already handled
                break;

            case 'L': {
                if ( idx >= argc )
                    return hilti::result::Error("argument missing");

                auto optarg = args[idx++];
                compiler_options->library_paths.emplace_back(optarg);
                break;
            }

            case 'O': compiler_options->optimize = true; break;

            case 'o': {
                if ( idx >= argc )
                    return hilti::result::Error("argument missing");

                auto optarg = args[idx++];
                driver_options->output_path = optarg;
                break;
            }

            case 'R': driver_options->report_times = true; break;

            case 'V': compiler_options->skip_validation = true; break;

            case 'X': {
                if ( idx >= argc )
                    return hilti::result::Error("argument missing");

                auto optarg = args[idx++];
                if ( auto r = compiler_options->parseDebugAddl(optarg); ! r )
                    return r.error();

                compiler_options->debug = true;
                break;
            }

            default: return hilti::result::Error(hilti::util::fmt("option -%c not supported", c));
        }
    }

    return hilti::Nothing();
}

hilti::Result<hilti::Nothing> Driver::loadFile(hilti::rt::filesystem::path file,
                                               const hilti::rt::filesystem::path& relative_to) {
    if ( ! relative_to.empty() && file.is_relative() ) {
        if ( auto p = relative_to / file; hilti::rt::filesystem::exists(p) )
            file = p;
    }

    if ( ! hilti::rt::filesystem::exists(file) ) {
        if ( auto path = hilti::util::findInPaths(file, hiltiOptions().library_paths) )
            file = *path;
        else
            return hilti::result::Error(hilti::util::fmt("Spicy plugin cannot find file %s", file));
    }

    auto rpath = hilti::util::normalizePath(file);
    auto ext = rpath.extension();

    if ( ext == ".evt" ) {
        ZEEK_DEBUG(hilti::util::fmt("Loading EVT file %s", rpath));
        if ( _glue->loadEvtFile(rpath) )
            return hilti::Nothing();
        else
            return hilti::result::Error(hilti::util::fmt("error loading EVT file %s", rpath));
    }

    if ( ext == ".spicy" ) {
        ZEEK_DEBUG(hilti::util::fmt("Loading Spicy file %s", rpath));
        if ( auto rc = addInput(rpath); ! rc )
            return rc.error();

        return hilti::Nothing();
    }

    if ( ext == ".hlt" ) {
        ZEEK_DEBUG(hilti::util::fmt("Loading HILTI file %s", rpath));
        if ( auto rc = addInput(rpath) )
            return hilti::Nothing();
        else
            return rc.error();
    }

    if ( ext == ".hlto" ) {
        ZEEK_DEBUG(hilti::util::fmt("Loading precompiled HILTI code %s", rpath));
        if ( auto rc = addInput(rpath) )
            return hilti::Nothing();
        else
            return rc.error();
    }

    return hilti::result::Error(hilti::util::fmt("unknown file type passed to Spicy loader: %s", rpath));
}

hilti::Result<hilti::Nothing> Driver::compile() {
    if ( ! hasInputs() )
        return hilti::Nothing();

    ZEEK_DEBUG("Running Spicy driver");

    if ( auto x = spicy::Driver::compile(); ! x )
        return x.error();

    ZEEK_DEBUG("Done with Spicy driver");
    return hilti::Nothing();
}

hilti::Result<UnitInfo> Driver::lookupUnit(const hilti::ID& unit) {
    if ( auto x = _units.find(unit); x != _units.end() )
        return x->second;
    else
        return hilti::result::Error("unknown unit");
}

void Driver::hookNewASTPreCompilation(const ID& id, const std::optional<hilti::rt::filesystem::path>& path,
                                      const hilti::Node& root) {
    if ( ! path )
        // Ignore modules constructed in memory.
        return;

    auto v = VisitorPreCompilation(this, id, *path);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    for ( const auto& e : v.enums ) {
        ZEEK_DEBUG(hilti::util::fmt("  Got public enum type '%s'", e.id));
        hookNewEnumType(e);
        _enums.push_back(e);
    }
}

void Driver::hookNewASTPostCompilation(const ID& id, const std::optional<hilti::rt::filesystem::path>& path,
                                       const hilti::Node& root) {
    if ( ! path )
        // Ignore modules constructed in memory.
        return;

    auto v = VisitorPostCompilation(this, id, *path);
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    for ( auto&& u : v.units ) {
        ZEEK_DEBUG(hilti::util::fmt("  Got unit type '%s'", u.id));
        hookNewUnitType(u);
        _units[u.id] = std::move(u);
    }

    if ( path.has_value() )
        _glue->addSpicyModule(id, *path);
}

hilti::Result<hilti::Nothing> Driver::hookCompilationFinished() {
    if ( ! _need_glue )
        return hilti::Nothing();

    _need_glue = false;

    if ( _glue->compile() )
        return hilti::Nothing();
    else
        return hilti::result::Error("glue compilation failed");
}

void Driver::hookInitRuntime() { spicy::rt::init(); }

void Driver::hookFinishRuntime() { spicy::rt::done(); }
