// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>
#include <getopt.h>

#include <algorithm>
#include <exception>
#include <fstream>
#include <iostream>
#include <system_error>
#include <utility>

#include <hilti/rt/libhilti.h>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/operator-registry.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/ast-dumper.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/plugin.h>

using namespace hilti;
using namespace hilti::detail;
using util::fmt;

namespace hilti::logging::debug {
inline const DebugStream AstCodegen("ast-codegen");
inline const DebugStream Compiler("compiler");
inline const DebugStream Driver("driver");
} // namespace hilti::logging::debug

constexpr int OptCxxLink = 1000;
constexpr int OptCxxEnableDynamicGlobals = 1001;
constexpr int OptSkipStdImports = 1002;

static struct option long_driver_options[] =
    {{.name = "abort-on-exceptions", .has_arg = required_argument, .flag = nullptr, .val = 'A'},
     {.name = "show-backtraces", .has_arg = no_argument, .flag = nullptr, .val = 'B'},
     {.name = "compiler-debug", .has_arg = required_argument, .flag = nullptr, .val = 'D'},
     {.name = "cxx-enable-dynamic-globals", .has_arg = no_argument, .flag = nullptr, .val = OptCxxEnableDynamicGlobals},
     {.name = "cxx-link", .has_arg = required_argument, .flag = nullptr, .val = OptCxxLink},
     {.name = "debug", .has_arg = no_argument, .flag = nullptr, .val = 'd'},
     {.name = "debug-addl", .has_arg = required_argument, .flag = nullptr, .val = 'X'},
     {.name = "disable-optimizations", .has_arg = no_argument, .flag = nullptr, .val = 'g'},
     {.name = "enable-profiling", .has_arg = no_argument, .flag = nullptr, .val = 'Z'},
     {.name = "dump-code", .has_arg = no_argument, .flag = nullptr, .val = 'C'},
     {.name = "help", .has_arg = no_argument, .flag = nullptr, .val = 'h'},
     {.name = "keep-tmps", .has_arg = no_argument, .flag = nullptr, .val = 'T'},
     {.name = "library-path", .has_arg = required_argument, .flag = nullptr, .val = 'L'},
     {.name = "output", .has_arg = required_argument, .flag = nullptr, .val = 'o'},
     {.name = "output-c++", .has_arg = no_argument, .flag = nullptr, .val = 'c'},
     {.name = "output-c++-files", .has_arg = no_argument, .flag = nullptr, .val = 'x'},
     {.name = "output-hilti", .has_arg = no_argument, .flag = nullptr, .val = 'p'},
     {.name = "execute-code", .has_arg = no_argument, .flag = nullptr, .val = 'j'},
     {.name = "output-linker", .has_arg = no_argument, .flag = nullptr, .val = 'l'},
     {.name = "output-prototypes", .has_arg = required_argument, .flag = nullptr, .val = 'P'},
     {.name = "output-all-dependencies", .has_arg = no_argument, .flag = nullptr, .val = 'e'},
     {.name = "output-code-dependencies", .has_arg = no_argument, .flag = nullptr, .val = 'E'},
     {.name = "report-times", .has_arg = required_argument, .flag = nullptr, .val = 'R'},
     {.name = "skip-validation", .has_arg = no_argument, .flag = nullptr, .val = 'V'},
     {.name = "skip-dependencies", .has_arg = no_argument, .flag = nullptr, .val = 'S'},
     {.name = "skip-standard-imports", .has_arg = no_argument, .flag = nullptr, .val = OptSkipStdImports},
     {.name = "version", .has_arg = no_argument, .flag = nullptr, .val = 'v'},
     {.name = nullptr, .has_arg = 0, .flag = nullptr, .val = 0}};

Driver::Driver(std::string name) : _name(std::move(name)) { configuration().initLocation(false); }

Driver::Driver(std::string name, const hilti::rt::filesystem::path& argv0) : _name(std::move(name)) {
    configuration().initLocation(argv0);
}

Driver::~Driver() {
    if ( _driver_options.report_times )
        try {
            util::timing::summary(std::cerr);
        } catch ( ... ) {
            // Nothing.
        }

    if ( ! _driver_options.keep_tmps ) {
        for ( const auto& t : _tmp_files )
            unlink(t.c_str());
    }
}

void Driver::usage() {
    auto exts = util::join(plugin::registry().supportedExtensions(), ", ");

    std::string addl_usage = hookAugmentUsage();
    if ( addl_usage.size() )
        addl_usage = std::string("\n") + addl_usage + "\n";

    std::cout
        << "Usage: " << _name
        << " [options] <inputs>\n"
           "\n"
           "Options controlling code generation:\n"
           "\n"
           "  -c | --output-c++                 Print out C++ code generated for module (for debugging; use -x to "
           "generate code for external compilation).\n"
           "  -d | --debug                      Include debug instrumentation into generated code.\n"
           "  -e | --output-all-dependencies    Output list of dependencies for all compiled modules.\n"
           "  -g | --disable-optimizations      Disable HILTI-side optimizations of the generated code.\n"
           "  -j | --jit-code                   Fully compile all code, and then execute it unless --output-to gives a "
           "file to store it\n"
           "  -l | --output-linker              Print out only generated HILTI linker glue code (for debugging; use -x "
           "to generate code for external compilation).\n"
           "  -o | --output-to <path>           Path for saving output.\n"
           "  -p | --output-hilti               Just output parsed HILTI code again.\n"
           "  -v | --version                    Print version information.\n"
           "  -x | --output-c++-files <prefix>  Output generated all C++ code into set of files for external "
           "compilation.\n"
           "  -A | --abort-on-exceptions        When executing compiled code, abort() instead of throwing HILTI "
           "exceptions.\n"
           "  -B | --show-backtraces            Include backtraces when reporting unhandled exceptions.\n"
           "  -C | --dump-code                  Dump all generated code to disk for debugging.\n"
           "  -D | --compiler-debug <streams>   Activate compile-time debugging output for given debug streams "
           "(comma-separated; 'help' for list).\n"
           "  -E | --output-code-dependencies   Output list of dependencies for all compiled modules that require "
           "separate compilation of their own.\n"
           "  -L | --library-path <path>        Add path to list of directories to search when importing modules.\n"
           "  -P | --output-prototypes <prefix> Output C++ header with prototypes for public functionality.\n"
           "  -R | --report-times               Report a break-down of compiler's execution time.\n"
           "  -S | --skip-dependencies          Do not automatically compile dependencies during JIT.\n"
           "  -T | --keep-tmps                  Do not delete any temporary files created.\n"
           "  -V | --skip-validation            Don't validate ASTs (for debugging only).\n"
           "  -X | --debug-addl <addl>          Implies -d and adds selected additional instrumentation "
           "(comma-separated; see 'help' for list).\n"
           "  -Z | --enable-profiling           Report profiling statistics after execution.\n"
           "       --cxx-link <lib>             Link specified static archive or shared library during JIT or to "
           "produced HLTO file. Can be given multiple times.\n"
           "       --skip-standard-imports      Do not automatically import standard library modules (for debugging "
           "only).\n"
        << addl_usage
        << "\n"
           "Inputs can be "
        << exts
        << ", .cc/.cxx, *.hlto.\n"
           "\n";
}

result::Error Driver::error(std::string_view msg, const hilti::rt::filesystem::path& p) {
    auto x = fmt("%s: %s", _name, msg);

    if ( ! p.empty() )
        x += fmt(" (%s)", p.native());

    return result::Error(std::move(x));
}

result::Error Driver::augmentError(const result::Error& err, const hilti::rt::filesystem::path& p) {
    return error(err.description(), p);
}

Result<std::ofstream> Driver::openOutput(const hilti::rt::filesystem::path& p, bool binary, bool append) {
    auto mode = std::ios::out;

    if ( append || p == "/dev/stdout" || p == "/dev/stderr" )
        mode |= std::ios::app;
    else
        mode |= std::ios::trunc;

    if ( binary )
        mode |= std::ios::binary;

    std::ofstream out(p, mode);

    if ( ! out.is_open() )
        return error("Cannot open file for output", p);

    return {std::move(out)};
}

Result<Nothing> Driver::openInput(std::ifstream& in, const hilti::rt::filesystem::path& p) {
    in.open(p);

    if ( ! in.is_open() )
        return error("Cannot open file for reading", p);

    return Nothing();
}

Result<std::stringstream> Driver::readInput(const hilti::rt::filesystem::path& p) {
    std::ifstream in;
    if ( auto x = openInput(in, p); ! x )
        return x.error();

    std::stringstream out;

    if ( ! util::copyStream(in, out) )
        return error("Error reading from file", p);

    return std::move(out);
}

Result<Nothing> Driver::writeOutput(std::ifstream& in, const hilti::rt::filesystem::path& p) {
    auto out = openOutput(p);

    if ( ! out )
        return out.error();

    if ( ! util::copyStream(in, *out) )
        return error("Error writing to file", p);

    return Nothing();
}

Result<hilti::rt::filesystem::path> Driver::writeToTemp(std::ifstream& in, const std::string& name_hint,
                                                        const std::string& extension) {
    auto template_ = fmt("%s.XXXXXX.%s", name_hint, extension);
    auto name = std::move(template_);
    auto fd = mkstemp(name.data());

    if ( fd < 0 )
        return error("Cannot open temporary file");

    // Not sure if this is safe, but it seems to be what everybody does ...
    std::ofstream out(name);
    close(fd);

    if ( ! util::copyStream(in, out) )
        return error("Error writing to file", {std::move(name)});

    _tmp_files.insert(name);
    return hilti::rt::filesystem::path(name);
}

void Driver::dumpUnit(const Unit& unit) {
    if ( auto* module = unit.module() ) {
        auto output_path = util::fmt("dbg.%s%s.ast", unit.uid().str(), unit.uid().process_extension.native());
        if ( auto out = openOutput(output_path) ) {
            HILTI_DEBUG(logging::debug::Driver, fmt("saving AST for module %s to %s", unit.uid().str(), output_path));
            ast_dumper::dump(*out, module, true);
        }
    }

    if ( unit.isCompiledHILTI() ) {
        auto output_path = util::fmt("dbg.%s%s", unit.uid().str(), unit.uid().process_extension.native());
        if ( auto out = openOutput(output_path) ) {
            HILTI_DEBUG(logging::debug::Driver, fmt("saving code for module %s to %s", unit.uid().str(), output_path));
            unit.print(*out);
        }
    }

    if ( auto cxx = unit.cxxCode() ) {
        ID id = (unit.isCompiledHILTI() ? ID(unit.uid().str()) : ID(unit.cxxCode().value().id()));
        auto output_path = util::fmt("dbg.%s.cc", id);
        if ( auto out = openOutput(util::fmt("dbg.%s.cc", id)) ) {
            HILTI_DEBUG(logging::debug::Driver, fmt("saving C++ code for module %s to %s", id, output_path));
            cxx->save(*out);
        }
    }
}

Result<Nothing> Driver::_setCxxNamespacesFromPrefix(const char* prefix) {
    auto s = hilti::rt::filesystem::path(prefix).stem().string();
    if ( s.empty() )
        return Nothing();

    if ( ! isdigit(s[0]) && std::ranges::all_of(s, [](auto c) { return std::isalnum(c) || c == '_'; }) ) {
        _compiler_options.cxx_namespace_extern = hilti::util::fmt("hlt_%s", s);
        _compiler_options.cxx_namespace_intern = hilti::util::fmt(HILTI_INTERNAL_GLOBAL_ID("%s"), s);
        return Nothing();
    }

    return error("C++ prefix must be a valid identifier");
}

Result<Nothing> Driver::parseOptions(int argc, char** argv) {
    int num_output_types = 0;

    opterr = 0; // don't print errors
    std::string option_string = "ABlL:cCpP:vjhvx:VdX:o:D:TUEeSRgZ" + hookAddCommandLineOptions();

    while ( true ) {
        int c = getopt_long(argc, argv, option_string.c_str(), long_driver_options, nullptr);

        if ( c < 0 )
            break;

        switch ( c ) {
            case 'A': _driver_options.abort_on_exceptions = true; break;

            case 'B': _driver_options.show_backtraces = true; break;

            case 'c':
                _driver_options.output_cxx = true;
                _driver_options.skip_dependencies = true;
                ++num_output_types;
                break;

            case 'x':
                _driver_options.output_cxx = true;
                _driver_options.output_cxx_prefix = optarg;
                _driver_options.execute_code = false;
                _driver_options.include_linker = true;

                if ( auto rc = _setCxxNamespacesFromPrefix(optarg); ! rc )
                    return rc;

                ++num_output_types;
                break;

            case 'C': {
                _driver_options.dump_code = true;
                break;
            }

            case 'd': {
                _compiler_options.debug = true;
                break;
            }

            case 'X': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cout << "Additional debug instrumentation:\n";
                    std::cout << "   flow:     log function calls to debug stream \"hilti-flow\"\n";
                    std::cout << "   location: track current source code location for error reporting\n";
                    std::cout << "   trace:    log statements to debug stream \"hilti-trace\"\n";
                    std::cout << "\n";
                    exit(0);
                }

                _compiler_options.debug = true;

                if ( auto r = _compiler_options.parseDebugAddl(arg); ! r )
                    error(r.error());

                break;
            }

            case 'D': {
                auto arg = std::string(optarg);

                if ( arg == "help" ) {
                    std::cout << "Debug streams:\n";

                    for ( const auto& s : logging::DebugStream::all() )
                        std::cout << "  " << s << "\n";

                    std::cout << "\n";
                    exit(0);
                }

                for ( const auto& s : util::split(arg, ",") ) {
                    if ( ! _driver_options.logger->debugEnable(s) )
                        return error(fmt("Unknown debug stream '%s', use 'help' for list", arg));
                }

                break;
            }

            case 'e':
                _driver_options.output_dependencies = driver::Dependencies::All;
                ++num_output_types;
                break;

            case 'E':
                _driver_options.output_dependencies = driver::Dependencies::Code;
                ++num_output_types;
                break;

            case 'j':
                _driver_options.execute_code = true;
                _driver_options.include_linker = true;
                ++num_output_types;
                break;

            case 'g': {
                _compiler_options.global_optimizations = false;
                break;
            }

            case 'l':
                _driver_options.output_linker = true;
                _driver_options.include_linker = true;
                ++num_output_types;
                break;

            case 'L': _compiler_options.library_paths.emplace_back(optarg); break;

            case 'o': _driver_options.output_path = std::string(optarg); break;

            case 'p':
                _driver_options.output_hilti = true;
                _driver_options.skip_dependencies = true;
                ++num_output_types;
                break;

            case 'P':
                _driver_options.output_prototypes = true;
                _driver_options.skip_dependencies = true;
                _driver_options.output_cxx_prefix = optarg;

                if ( auto rc = _setCxxNamespacesFromPrefix(optarg); ! rc )
                    return rc;

                ++num_output_types;
                break;

            case 'R': _driver_options.report_times = true; break;

            case 'S': _driver_options.skip_dependencies = true; break;

            case 'T':
                _driver_options.keep_tmps = true;
                _compiler_options.keep_tmps = true;
                break;

            case 'U': _driver_options.report_resource_usage = true; break;

            case 'v':
                std::cout << _name << " v" << hilti::configuration().version_string_long << '\n';
                return Nothing();

            case 'V': _compiler_options.skip_validation = true; break;

            case 'Z':
                _compiler_options.enable_profiling = true;
                _driver_options.enable_profiling = true;
                break;

            case OptCxxLink: _compiler_options.cxx_link.emplace_back(optarg); break;

            case OptCxxEnableDynamicGlobals: _compiler_options.cxx_enable_dynamic_globals = true; break;

            case OptSkipStdImports: _compiler_options.import_standard_modules = false; break;

            case 'h': usage(); return Nothing();

            case '?':
                if ( optopt )
                    fatalError(fmt("option '%s' requires an argument; try --help for usage", argv[optind - 1]));
                else
                    fatalError(fmt("option '%s' not supported; try --help for usage", argv[optind - 1]));

            default:
                if ( hookProcessCommandLineOption(c, optarg) )
                    break;

                fatalError(fmt("option '%s' not implemented; try --help for usage", argv[optind - 1]));
        }
    }

    while ( optind < argc )
        _driver_options.inputs.emplace_back(argv[optind++]);

    if ( _driver_options.inputs.empty() )
        return error("no input file given");

    if ( num_output_types > 1 )
        return error("only one type of output can be specified");

    if ( num_output_types == 0 )
        return error("no output type given");

    if ( ! _compiler_options.debug ) {
        if ( _compiler_options.debug_trace || _compiler_options.debug_flow )
            return error("must use --debug with --cgdebug");
    }

    if ( _driver_options.execute_code && ! _driver_options.output_path.empty() ) {
        if ( ! util::endsWith(_driver_options.output_path, ".hlto") )
            return error("output will be a precompiled object file and must have '.hlto' extension");
    }

    return Nothing();
}

Result<Nothing> Driver::initialize() {
    if ( _stage != Stage::UNINITIALIZED )
        logger().internalError("unexpected driver stage in initialize()");

    _stage = INITIALIZED;

    util::removeDuplicates(_compiler_options.cxx_include_paths);
    util::removeDuplicates(_compiler_options.library_paths);

    if ( _driver_options.logger )
        setLogger(std::move(_driver_options.logger));

    if ( getenv("HILTI_PRINT_SETTINGS") )
        _compiler_options.print(std::cerr);

    _ctx = std::make_shared<Context>(_compiler_options);
    _builder = createBuilder(_ctx->astContext());

    operator_::registry().initPending(_builder.get());

    return Nothing();
}

void Driver::setCompilerOptions(hilti::Options options) {
    if ( _stage != Stage::UNINITIALIZED )
        logger().internalError("setCompilerOptions() must be called before initialization");

    _compiler_options = std::move(options);
}

void Driver::setDriverOptions(driver::Options options) {
    if ( _stage != Stage::UNINITIALIZED )
        logger().internalError("setCompilerOptions() must be called before initialization");

    _driver_options = std::move(options);
}

void Driver::updateProcessExtension(const declaration::module::UID& uid, const hilti::rt::filesystem::path& ext) {
    auto i = _units.find(uid);
    if ( i == _units.end() )
        logger().internalError(util::fmt("attempt to update unknown unit %s", uid));

    auto unit = i->second;
    auto new_uid = uid;
    new_uid.process_extension = ext;

    if ( _units.contains(new_uid) )
        logger().internalError(
            util::fmt("attempt to update process extension of unit %s to %s, but that already exists", uid,
                      ext.native()));


    HILTI_DEBUG(logging::debug::Driver,
                fmt("updating process extension of unit %s (%s) to %s", unit->uid(), unit->uid().path.native(), ext));

    context()->astContext()->updateModuleUID(uid, new_uid);

    unit->setUID(new_uid);
    _units.erase(i);
    _units.emplace(new_uid, unit);
}

void Driver::_addUnit(const std::shared_ptr<Unit>& unit) {
    if ( _units.contains(unit->uid()) )
        return;

    HILTI_DEBUG(logging::debug::Driver, fmt("adding unit %s (%s)", unit->uid(), unit->uid().path.native()));
    unit->module()->setSkipImplementation(false);
    _units.emplace(unit->uid(), unit);
}

Result<void*> Driver::_symbol(const std::string& symbol) {
    // Since `NULL` could be the address of a function, use `::dlerror` to
    // detect errors. Since `::dlerror` resets the error state when called we
    // can drive its state explicitly.

    ::dlerror(); // Resets error state.
    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    auto* sym = ::dlsym(RTLD_DEFAULT, symbol.c_str());

    // We return an error if the symbol could not be looked up, or if the
    // address of the symbol is `NULL`.
    if ( auto* error = ::dlerror() )
        return result::Error(error);
    else if ( ! sym )
        return result::Error(util::fmt("address of symbol is %s", sym));

    return sym;
}

Result<Nothing> Driver::addInput(const hilti::rt::filesystem::path& path) {
    auto path_normalized = path.lexically_normal();
    if ( path_normalized.is_relative() ) {
        std::error_code ec;
        path_normalized = rt::filesystem::absolute(path_normalized, ec);
        if ( ec )
            return result::Error(fmt("could not compute absolute path for %s", path_normalized));
    }

    if ( _processed_paths.contains(path_normalized.native()) )
        return Nothing();

    // Calling hook before stage check so that it can execute initialize()
    // just in time if it so desires.
    hookAddInput(path);

    if ( _stage == Stage::UNINITIALIZED )
        logger().internalError(" driver must be initialized before inputs can be added");

    if ( _stage != Stage::INITIALIZED )
        logger().internalError("no further inputs can be added after compilation has finished already");

    if ( plugin::registry().supportsExtension(path.extension()) ) {
        HILTI_DEBUG(logging::debug::Driver, fmt("parsing input file %s", path));
        auto unit = Unit::fromSource(context(), _builder.get(), path);
        if ( ! unit )
            return augmentError(unit.error());

        (*unit)->setRequiresCompilation();
        _addUnit(*unit);
    }

    else if ( path.extension() == ".cc" || path.extension() == ".cxx" ) {
        if ( _compiler_options.global_optimizations ) {
            // When optimizing we only support including truly external C++ code,
            // but e.g., not code generated by us since it might depend on code
            // which might become optimized away. We can detect generated code by
            // checking whether the input file has any linker metadata which we
            // always include when emitting C++.
            // TODO: Do this differently
            /*
             * std::fstream file(path);
             * auto [_, md] = Unit::readLinkerMetaData(file, path);
             * if ( md ) {
             *     return result::Error(
             *         "Loading generated C++ files is not supported with transformations enabled, rerun with '-g'");
             * }
             */
        }

        HILTI_DEBUG(logging::debug::Driver, fmt("adding external C++ file %s", path));
        _external_cxxs.push_back(path);
    }

    else if ( path.extension() == ".hlto" ) {
        HILTI_DEBUG(logging::debug::Driver, fmt("adding precompiled HILTI file %s", path));

        try {
            if ( ! _libraries.contains(path) ) {
                _libraries.insert({path, Library(path)});
                if ( auto load = _libraries.at(path).open(); ! load )
                    return error(util::fmt("could not load library file %s: %s", path, load.error()));
            }
        } catch ( const hilti::rt::EnvironmentError& e ) {
            hilti::rt::fatalError(e.what());
        }
    }

    else
        return error("unsupported file type", path);

    _processed_paths.insert(path_normalized.native());

    return Nothing();
}

Result<Nothing> Driver::addInput(declaration::module::UID uid) {
    if ( ! context()->astContext()->module(uid) )
        return error(fmt("in-memory module %s does not exist", uid.unique));

    auto unit = Unit::fromExistingUID(context(), std::move(uid));
    assert(unit);

    unit->setRequiresCompilation();
    _addUnit(unit);

    return Nothing();
}

Result<Nothing> Driver::_codegenUnits() {
    if ( _stage != Stage::COMPILED )
        logger().internalError("unexpected driver stage in codegenUnits()");

    context()->astContext()->dump(logging::debug::AstCodegen, "Before C++ codegen");

    if ( _driver_options.output_hilti && ! _driver_options.include_linker )
        // No need to kick off code generation.
        return Nothing();

    for ( auto& [uid, unit] : _units ) {
        if ( ! unit->isCompiledHILTI() )
            continue;

        HILTI_DEBUG(logging::debug::Driver, fmt("codegen for input unit %s", unit->uid().str()));

        if ( auto rc = unit->codegen(); ! rc )
            return augmentError(rc.error());

        if ( ! unit->module()->skipImplementation() ) {
            if ( auto md = unit->linkerMetaData() )
                _mds.push_back(*md);
        }

        if ( _driver_options.dump_code )
            dumpUnit(*unit);
    }

    _stage = Stage::CODEGENED;
    return Nothing();
}

Result<Nothing> Driver::compileUnits() {
    assert(_builder);

    if ( auto rc = context()->astContext()->processAST(_builder.get(), this); ! rc ) {
        // hilti::detail::printer::print(std::cerr, context()->astContext()->root());
        return error(result::Error("aborting after errors"));
    }

    _stage = COMPILED;

    for ( const auto& [uid, unit] : _units ) {
        if ( _driver_options.dump_code )
            dumpUnit(*unit);
    }

    if ( _driver_options.output_hilti ) {
        std::string output_path = (_driver_options.output_path.empty() ? "/dev/stdout" : _driver_options.output_path);
        auto output = openOutput(output_path, false);
        if ( ! output )
            return error(output.error());

        for ( auto& [uid, unit] : _units ) {
            if ( ! unit->isCompiledHILTI() )
                continue;

            HILTI_DEBUG(logging::debug::Driver, util::fmt("saving HILTI code for module %s", unit->uid().str()));
            if ( ! unit->print(*output) )
                return error(fmt("error print HILTI code for module %s", unit->uid().str()));
        }
    }
    else {
        if ( auto rc = _codegenUnits(); ! rc )
            return error(rc.error());
    }

    return Nothing();
}

Result<Nothing> Driver::run() {
    assert(! _builder);
    initialize();
    assert(_builder);

    for ( const auto& i : _driver_options.inputs ) {
        if ( auto rc = addInput(i); ! rc )
            return rc;
    }

    if ( auto x = compile(); ! x )
        return x.error();

    if ( ! _driver_options.execute_code || ! _driver_options.output_path.empty() )
        return Nothing();

    try {
        util::timing::Collector _("hilti/runtime");

        if ( auto x = initRuntime(); ! x )
            return x;

        if ( auto x = executeMain(); ! x )
            return x;

        if ( auto x = finishRuntime(); ! x )
            return x;

        return Nothing();

    } catch ( const std::exception& e ) {
        return result::Error(fmt("uncaught exception of type %s: %s", util::demangle(typeid(e).name()), e.what()));
    }

    util::cannotBeReached();
}

Result<Nothing> Driver::compile() {
    if ( auto rc = compileUnits(); ! rc )
        return rc;

    if ( _driver_options.include_linker ) {
        if ( auto rc = linkUnits(); ! rc )
            return error(rc.error());
    }

    if ( _driver_options.output_hilti )
        return Nothing();

    if ( auto rc = outputUnits(); ! rc )
        return error(rc.error());

    if ( _driver_options.execute_code && ! _driver_options.output_prototypes ) {
        context()->astContext()->clear(); // release memory

        if ( auto rc = jitUnits(); ! rc )
            return error(rc.error());

        if ( _driver_options.output_path.empty() ) {
            // OK if not available.
            if ( _library ) {
                if ( auto loaded = _library->open(); ! loaded )
                    return loaded.error();
            }
        }
        else {
            // Save code to disk rather than execute.
            if ( ! _library )
                // We don't have any code.
                return result::Error("no library compiled");

            HILTI_DEBUG(logging::debug::Driver, fmt("saving precompiled code to %s", _driver_options.output_path));

            if ( auto success = _library->save(_driver_options.output_path); ! success )
                return result::Error(
                    fmt("error saving object code to %s: %s", _driver_options.output_path, success.error()));
        }
    }

    return Nothing();
}

Result<Nothing> Driver::linkUnits() {
    if ( _stage != Stage::CODEGENED )
        logger().internalError("unexpected driver stage in linkModule()");

    _stage = Stage::LINKED;

    if ( _mds.empty() && _external_cxxs.empty() )
        return Nothing();

    HILTI_DEBUG(logging::debug::Driver, "linking modules");
    for ( const auto& md : _mds ) {
        HILTI_DEBUG(logging::debug::Driver, fmt("  - %s", md.module));
    }

    auto linker_unit = Unit::link(_ctx, _mds);
    if ( ! linker_unit )
        return error("aborting after linker errors");

    auto cxx_code = (*linker_unit)->cxxCode();
    assert(cxx_code);

    if ( _driver_options.output_linker ) {
        std::string output_path = (_driver_options.output_path.empty() ? "/dev/stdout" : _driver_options.output_path);

        auto output = openOutput(output_path, false);
        if ( ! output )
            return output.error();

        HILTI_DEBUG(logging::debug::Driver, fmt("writing linker code to %s", output_path));
        cxx_code->save(*output);
        return Nothing(); // All done.
    }

    if ( _driver_options.dump_code )
        dumpUnit(**linker_unit);

    if ( cxx_code->code() && cxx_code->code()->size() )
        _units.emplace((*linker_unit)->uid(), *linker_unit);

    return Nothing();
}

Result<Nothing> Driver::outputUnits() {
    if ( _stage != Stage::COMPILED && _stage != Stage::CODEGENED && _stage != Stage::LINKED )
        logger().internalError("unexpected driver stage in outputUnits()");

    std::string output_path = (_driver_options.output_path.empty() ? "/dev/stdout" : _driver_options.output_path);

    bool append = false;
    for ( auto& [uid, unit] : _units ) {
        if ( unit->module() && unit->module()->skipImplementation() )
            continue;

        if ( auto cxx = unit->cxxCode() ) {
            if ( _driver_options.output_cxx ) {
                auto cxx_path = output_path;

                if ( _driver_options.output_cxx_prefix.size() ) {
                    assert(cxx->id().size());

                    if ( util::endsWith(_driver_options.output_cxx_prefix, "/") ) {
                        hilti::rt::filesystem::create_directory(_driver_options.output_cxx_prefix);
                        cxx_path = fmt("%s%s.cc", _driver_options.output_cxx_prefix, cxx->id());
                    }
                    else
                        cxx_path = fmt("%s_%s.cc", _driver_options.output_cxx_prefix, cxx->id());
                }

                auto output = openOutput(cxx_path, false, append);
                if ( ! output )
                    return output.error();

                HILTI_DEBUG(logging::debug::Driver,
                            fmt("saving C++ code for module %s to %s", unit->uid().str(), cxx_path));
                cxx->save(*output);
            }

            if ( _driver_options.output_prototypes ) {
                auto output = openOutput(output_path, false, append);
                if ( ! output )
                    return output.error();

                HILTI_DEBUG(logging::debug::Driver,
                            fmt("saving C++ prototypes for module %s to %s", unit->uid().str(), output_path));
                unit->createPrototypes(*output);
            }

            _generated_cxxs.push_back(std::move(*cxx));

            // Append further code to same output file if we aren't
            // individually prefixing names.
            append = _driver_options.output_cxx_prefix.empty();
        }
        else
            return error(fmt("error for module %s: %s", unit->uid().str(), cxx.error()));
    }

    return Nothing();
}

Result<Nothing> Driver::jitUnits() {
    if ( _stage != Stage::LINKED )
        logger().internalError("unexpected driver stage in jitModule()");

    _stage = Stage::JITTED;

    static util::timing::Ledger ledger("hilti/jit");
    util::timing::Collector _(&ledger);

    HILTI_DEBUG(logging::debug::Driver, "JIT modules:");

    auto jit = std::make_unique<hilti::JIT>(_ctx, _driver_options.dump_code);

    for ( const auto& cxx : _generated_cxxs ) {
        HILTI_DEBUG(logging::debug::Driver, fmt("  - %s", cxx.id()));
        jit->add(cxx);
    }

    for ( const auto& cxx : _external_cxxs ) {
        HILTI_DEBUG(logging::debug::Driver, fmt("  - %s", cxx));
        jit->add(cxx);
    }

    if ( ! jit->hasInputs() )
        return Nothing();

    auto lib = jit->build();
    if ( ! lib )
        return lib.error();

    _library = std::move(*lib);
    return Nothing();
}

void Driver::printHiltiException(const hilti::rt::Exception& e) {
    std::cerr << fmt("uncaught exception %s: %s", util::demangle(typeid(e).name()), e.what()) << '\n';

    if ( ! _driver_options.show_backtraces )
        return;

    if ( ! e.backtrace() )
        return;

    auto bt = e.backtrace()->backtrace();
    if ( bt->empty() )
        return;

    std::cerr << "backtrace:\n";

    for ( const auto& s : *bt )
        std::cerr << "  " << s << "\n";
}

std::unique_ptr<Builder> Driver::createBuilder(ASTContext* ctx) const { return std::make_unique<Builder>(ctx); }

Result<Nothing> Driver::initRuntime() {
    util::timing::Collector _("hilti/runtime/init");

    if ( _runtime_initialized )
        return Nothing();

    auto config = hilti::rt::configuration::get();
    config.abort_on_exceptions = _driver_options.abort_on_exceptions;
    config.show_backtraces = _driver_options.show_backtraces;
    config.report_resource_usage = _driver_options.report_resource_usage;
    config.enable_profiling = _driver_options.enable_profiling;
    hilti::rt::configuration::set(std::move(config));

    try {
        HILTI_DEBUG(logging::debug::Driver, "initializing runtime");
        rt::init();
        hookInitRuntime();
    } catch ( const hilti::rt::Exception& e ) {
        printHiltiException(e);
        hookFinishRuntime();
        finishRuntime();
        exit(1);
    } catch ( const std::runtime_error& e ) {
        std::cerr << fmt("uncaught C++ exception %s: %s", util::demangle(typeid(e).name()), e.what()) << '\n';
        hookFinishRuntime();
        finishRuntime();
        exit(1);
    }

    _runtime_initialized = true;
    return Nothing();
}

Result<Nothing> Driver::executeMain() {
    util::timing::Collector _("hilti/runtime/main");

    int rc = 0;

    if ( auto main = _symbol("hilti_main") ) {
        HILTI_DEBUG(logging::debug::Driver, "executing main() function");

        using main_t = int();

        try {
            rc = (*(reinterpret_cast<main_t*>(*main)))();
        } catch ( const hilti::rt::Exception& e ) {
            printHiltiException(e);
            finishRuntime();
            exit(1);
        } catch ( const std::runtime_error& e ) {
            std::cerr << fmt("uncaught C++ exception %s: %s", util::demangle(typeid(e).name()), e.what()) << '\n';
            finishRuntime();
            exit(1);
        }
    }

    if ( rc == 0 )
        return Nothing();

    return error(fmt("hilti_main() returned exit code %d", rc));
}

Result<Nothing> Driver::finishRuntime() {
    util::timing::Collector _("hilti/runtime/finish");

    if ( _runtime_initialized ) {
        HILTI_DEBUG(logging::debug::Driver, "shutting down runtime");
        hookFinishRuntime();
        rt::done();
        _runtime_initialized = false;
    }

    _jit.reset();
    _library.reset();

    return Nothing();
}

void Driver::fatalError(const std::string& msg) {
    hilti::logger().error(msg);
    finishRuntime();
    exit(1);
}

void Driver::fatalError(const hilti::result::Error& error) {
    hilti::logger().error(error.description());

    if ( error.context().size() )
        hilti::logger().error(error.context());

    finishRuntime();
    exit(1);
}
