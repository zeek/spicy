// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <utility>

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/base/visitor.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using namespace hilti::context;
using util::fmt;

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
inline const DebugStream AstFinal("ast-final");
inline const DebugStream AstOrig("ast-orig");
inline const DebugStream AstResolved("ast-resolved");
inline const DebugStream AstScopes("ast-scopes");
inline const DebugStream AstPreTransformed("ast-pre-transformed");
inline const DebugStream AstTransformed("ast-transformed");
inline const DebugStream AstDumpIterations("ast-dump-iterations");
} // namespace hilti::logging::debug

template<typename PluginMember, typename... Args>
bool runHooks(PluginMember hook, const std::string& debug_msg, const Args&... args) {
    for ( const auto& p : plugin::registry().plugins() ) {
        if ( ! (p.*hook) )
            continue;

        auto msg = debug_msg;

        if ( p.component != "HILTI" )
            msg += fmt(" (%s)", p.component);

        HILTI_DEBUG(logging::debug::Compiler, msg);
        (*(p.*hook))(args...);

        if ( logger().errors() )
            return false;
    }

    return true;
}

template<typename PluginMember, typename... Args>
bool runModifyingHooks(bool* modified, PluginMember hook, const std::string& debug_msg, const Args&... args) {
    for ( const auto& p : plugin::registry().plugins() ) {
        if ( ! (p.*hook) )
            continue;

        auto msg = debug_msg;

        if ( p.component != "HILTI" )
            msg += fmt(" (%s)", p.component);

        HILTI_DEBUG(logging::debug::Compiler, msg);
        if ( (*(p.*hook))(args...) ) {
            *modified = true;
            HILTI_DEBUG(logging::debug::Compiler, "  -> modified");
        }

        if ( logger().errors() )
            return false;
    }

    return true;
}

Result<Unit> Unit::fromModule(const std::shared_ptr<Context>& context, hilti::Module&& module,
                              const hilti::rt::filesystem::path& path) {
    auto unit = Unit(context, module.id(), path, true);
    auto cached = context->registerModule({unit.id(), path}, std::move(module), true);
    unit._modules.insert(cached.index.id);
    return unit;
}

Result<Unit> Unit::fromCache(const std::shared_ptr<Context>& context, const hilti::rt::filesystem::path& path) {
    auto cached = context->lookupModule(path);
    if ( ! cached )
        return result::Error(fmt("unknown module %s", path));

    auto unit = Unit(context, cached->index.id, cached->index.path, true);
    unit._modules.insert(cached->index.id);
    return unit;
}

Result<Unit> Unit::fromCache(const std::shared_ptr<Context>& context, const hilti::ID& id) {
    auto cached = context->lookupModule(id);
    if ( ! cached )
        return result::Error(fmt("unknown module %s", id));

    auto unit = Unit(context, cached->index.id, cached->index.path, true);
    unit._modules.insert(cached->index.id);
    return unit;
}

Result<Unit> Unit::fromSource(const std::shared_ptr<Context>& context, const hilti::rt::filesystem::path& path) {
    auto module = Unit::parse(context, path);
    if ( ! module )
        return module.error();

    return fromModule(context, std::move(*module), path);
}

Result<Unit> Unit::fromCXX(std::shared_ptr<Context> context, detail::cxx::Unit cxx,
                           const hilti::rt::filesystem::path& path) {
    auto unit = Unit(std::move(context), ID(fmt("<CXX/%s>", path.native())), path, false);
    unit._cxx_unit = std::move(cxx);
    // No entry in _modules.
    return unit;
}

Result<hilti::Module> Unit::parse(const std::shared_ptr<Context>& context, const hilti::rt::filesystem::path& path) {
    util::timing::Collector _("hilti/compiler/parser");

    std::ifstream in;
    in.open(path);

    if ( ! in )
        return result::Error(fmt("cannot open source file %s", path));

    auto plugin = plugin::registry().pluginForExtension(path.extension());

    if ( ! (plugin && plugin->parse) )
        return result::Error(fmt("no plugin provides support for importing *%s files", path.extension()));

    auto dbg_message = fmt("parsing file %s", path);

    if ( plugin->component != "HILTI" )
        dbg_message += fmt(" (%s)", plugin->component);

    HILTI_DEBUG(logging::debug::Compiler, dbg_message);

    auto module = (*plugin->parse)(in, path);
    if ( ! module )
        return module.error();

    return module->as<hilti::Module>();
}

Result<Nothing> Unit::compile() {
    _dumpASTs(logging::debug::AstOrig, "Original AST");
    _saveIterationASTs("AST before first iteration");

    int round = 1;
    int extra_rounds = 0; // set to >0 for debugging

    while ( true ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("processing AST, round %d", round));
        logging::DebugPushIndent _(logging::debug::Compiler);

        bool modified = false;

        std::set<ID> performed_imports;
        while ( true ) {
            auto orig_modules = _modules; // _modules may be modified by importer pass

            for ( const auto& id : orig_modules ) {
                if ( performed_imports.find(id) != performed_imports.end() )
                    continue;

                auto cached = _context->lookupModule(id);
                assert(cached);

                HILTI_DEBUG(logging::debug::Compiler, fmt("performing missing imports for module %s", id));
                {
                    logging::DebugPushIndent _(logging::debug::Compiler);
                    cached->dependencies = detail::importModules(*cached->node, this);
                    _context->updateModule(*cached);
                    performed_imports.insert(id);
                }
            }

            if ( logger().errors() )
                return result::Error("errors encountered during import");

            if ( _modules.size() == orig_modules.size() )
                // repeat while as long as we keep adding modules
                break;
        }

        HILTI_DEBUG(logging::debug::Compiler, fmt("modules: %s", util::join(_modules, ", ")));

        auto modules = _currentModules();

        for ( auto& [id, module] : modules )
            _resetNodes(id, &*module);

        if ( ! runHooks(&Plugin::build_scopes, "building scopes for all module modules", context(), modules, this) )
            return result::Error("errors encountered during scope building");

        _dumpASTs(logging::debug::AstScopes, "AST with scopes", round);

        if ( logger().errors() )
            return result::Error("errors encountered during scope building");

        for ( auto& [id, module] : modules ) {
            if ( ! runModifyingHooks(&modified, &Plugin::resolve_ids, fmt("resolving IDs in module %s", id), context(),
                                     &*module, this) )
                return result::Error("errors encountered during ID resolving");
        }

        for ( auto& [id, module] : modules ) {
            if ( ! runModifyingHooks(&modified, &Plugin::resolve_operators, fmt("resolving operators in module %s", id),
                                     context(), &*module, this) )
                return result::Error("errors encountered during operator resolving");
        }

        for ( auto& [id, module] : modules ) {
            if ( ! runModifyingHooks(&modified, &Plugin::apply_coercions, fmt("coercing expressions for %s", id),
                                     context(), &*module, this) )
                return result::Error("errors encountered during expression coercion");
        }

        _dumpASTs(logging::debug::AstResolved, "AST after resolving", round);

        if ( plugin::registry().hasHookFor(&Plugin::transform) ) {
            _dumpASTs(logging::debug::AstPreTransformed, "Pre-transformed AST", round);

            for ( auto& [id, module] : modules ) {
                bool found_errors = false;

                if ( ! runHooks(&Plugin::pre_validate, fmt("validating module %s (pre-transform)", id), context(),
                                &*module, this, &found_errors) )
                    return result::Error("errors encountered during pre-transform validation");

                if ( found_errors ) {
                    // We may have errors already set in the AST that we
                    // don't want to report, as normally they'd go away
                    // during further cycles. So we clear the AST and then
                    // run the hook again to get just the errors that it puts
                    // in place.
                    detail::clearErrors(&*module);
                    auto valid = _validateAST(id, NodeRef(module), [&](const ID& id, NodeRef& module) {
                        bool found_errors = false;
                        return runHooks(&Plugin::pre_validate,
                                        fmt("validating module %s (pre-transform, 2nd pass)", id), context(), &*module,
                                        this, &found_errors);
                    });

                    (void)valid;     // Fore use of `valid` since below `assert` might become a noop.
                    assert(! valid); // We already know it's failing.
                    _dumpAST(module, logging::debug::AstFinal, "Final AST");
                    _saveIterationASTs("Final AST", round);
                    return result::Error("errors encountered during pre-transform validation");
                }

                if ( ! runModifyingHooks(&modified, &Plugin::transform, fmt("transforming module %s", id), context(),
                                         &*module, round == 1, this) )
                    return result::Error("errors encountered during source-to-source translation");
            }

            _dumpASTs(logging::debug::AstTransformed, "Transformed AST", round);
        }

        if ( ! modified && extra_rounds-- == 0 )
            break;

        _saveIterationASTs("AST after iteration", round);

        if ( ++round >= 50 )
            logger().internalError("hilti::Unit::compile() didn't terminate, AST keeps changing");
    }

    auto& module = imported(_id);
    auto current = _currentModules();

    for ( auto& [id, module] : current ) {
        auto valid =
            _validateASTs(module->as<Module>().id(), (*module).as<Module>().preserved(),
                          [&](const ID& id, auto& preserved) {
                              for ( auto& m : preserved )
                                  _resetNodes(id, &m);

                              return runHooks(&Plugin::preserved_validate, fmt("validating module %s (preserved)", id),
                                              context(), &preserved, this);
                          });

        if ( ! valid ) {
            _dumpAST(module, logging::debug::AstFinal, "Final AST");
            _saveIterationASTs("Final AST", round);
            return result::Error("errors encountered during validation of preserved nodes");
        }
    }

    auto valid = _validateASTs(current, [&](const ID& id, NodeRef& module) {
        return runHooks(&Plugin::post_validate, fmt("validating module %s (post-transform)", id), context(), &*module,
                        this);
    });

    _dumpAST(module, logging::debug::AstFinal, "Final AST");
    _saveIterationASTs("Final AST", round);

    if ( ! valid )
        return result::Error("errors encountered during post-transform validation");

    for ( auto& [id, module] : _currentModules() ) {
        _determineCompilationRequirements(*module);

        // Cache the module's final state.
        auto cached = _context->lookupModule(id);
        cached->final = true;
        _context->updateModule(*cached);
    }

    return Nothing();
}

Result<Nothing> Unit::codegen() {
    auto& module = imported(_id);

    HILTI_DEBUG(logging::debug::Compiler, fmt("compiling module %s to C++", _id));
    logging::DebugPushIndent _(logging::debug::Compiler);

    // Compile to C++.
    auto c = detail::CodeGen(_context).compileModule(module, this, true);

    if ( logger().errors() )
        return result::Error("errors encountered during code generation");

    if ( ! c )
        logger().internalError(
            fmt("code generation for module %s failed, but did not log error (%s)", _id, c.error().description()));

    // Now compile the other modules to because we may need some of their
    // declarations.
    //
    // TODO(robin): Would be nice if we had a "cheap" compilation mode
    // that only generated declarations.
    for ( auto& [id, module] : _currentModules() ) {
        if ( id == _id )
            continue;

        HILTI_DEBUG(logging::debug::Compiler, fmt("importing declarations from module %s", id));
        auto other = detail::CodeGen(_context).compileModule(*module, this, false);
        c->importDeclarations(*other);
    }

    HILTI_DEBUG(logging::debug::Compiler, fmt("finalizing module %s", _id));
    if ( auto x = c->finalize(); ! x )
        return x.error();

    _cxx_unit = *c;
    return Nothing();
}

std::vector<std::pair<ID, NodeRef>> Unit::_currentModules() const {
    std::vector<std::pair<ID, NodeRef>> modules;

    for ( const auto& id : _modules ) {
        auto cached = _context->lookupModule(id);
        assert(cached);
        modules.emplace_back(id, NodeRef(cached->node));
    }

    return modules;
}

std::optional<CachedModule> Unit::_lookupModule(const ID& id) const {
    if ( _modules.find(id) == _modules.end() )
        return {};

    auto cached = _context->lookupModule(id);
    assert(cached);
    return cached;
}

Result<Nothing> Unit::print(std::ostream& out) const {
    detail::printAST(imported(_id), out);
    return Nothing();
}

Result<Nothing> Unit::createPrototypes(std::ostream& out) {
    if ( ! _cxx_unit )
        return result::Error("no C++ code available for unit");

    return _cxx_unit->createPrototypes(out);
}

Result<CxxCode> Unit::cxxCode() const {
    if ( ! _cxx_unit )
        return result::Error("no C++ code available for unit");

    std::stringstream cxx;
    _cxx_unit->print(cxx);

    if ( logger().errors() )
        return result::Error("errors during prototype creation");

    return CxxCode{_cxx_unit->moduleID(), cxx};
}

Result<ModuleIndex> Unit::import(const ID& id, const hilti::rt::filesystem::path& ext, std::optional<ID> scope,
                                 std::vector<hilti::rt::filesystem::path> search_dirs) {
    if ( auto cached = _lookupModule(id) )
        return cached->index;

    if ( auto cached = _context->lookupModule(id) ) {
        _modules.insert(id);
        return cached->index;
    }

    auto plugin = plugin::registry().pluginForExtension(ext);

    if ( ! (plugin && plugin->parse) )
        return result::Error(fmt("no plugin provides support for importing *%s files", ext));

    auto name = fmt("%s%s", util::tolower(id), ext.native());

    if ( scope )
        name = fmt("%s/%s", util::replace(scope->str(), ".", "/"), name);

    std::vector<hilti::rt::filesystem::path> library_paths = std::move(search_dirs);

    if ( plugin->library_paths )
        library_paths = util::concat(std::move(library_paths), (*plugin->library_paths)(context()));

    library_paths = util::concat(std::move(library_paths), options().library_paths);

    auto path = util::findInPaths(name, library_paths);
    if ( ! path ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("Failed to find module '%s' in search paths:", name));
        for ( const auto& p : library_paths )
            HILTI_DEBUG(logging::debug::Compiler, fmt("  %s", p));

        return result::Error(fmt("cannot find file"));
    }

    return _import(*path, id);
}

Result<ModuleIndex> Unit::import(const hilti::rt::filesystem::path& path) {
    if ( auto cached = _context->lookupModule(path) ) {
        _modules.insert(cached->index.id);
        return cached->index;
    }

    return _import(path, {});
}

Result<ModuleIndex> Unit::_import(const hilti::rt::filesystem::path& path, std::optional<ID> expected_name) {
    auto module = parse(context(), path);
    if ( ! module )
        return module.error();

    auto id = module->id();

    if ( expected_name && id != *expected_name )
        return result::Error(fmt("file %s does not contain expected module %s (but %s)", path, *expected_name, id));

    HILTI_DEBUG(logging::debug::Compiler, fmt("loaded module %s from %s", id, path));

    if ( auto cached = _lookupModule(id) )
        return cached->index;

    auto cached = context()->registerModule({id, path}, std::move(*module), false);
    cached.dependencies = detail::importModules(*cached.node, this);
    context()->updateModule(cached);
    _modules.insert(id);
    return cached.index;
}

Node& Unit::imported(const ID& id) const {
    if ( auto cached = _lookupModule(id) )
        return *cached->node;
    else
        throw std::out_of_range("no such module");
}

void Unit::_determineCompilationRequirements(const Node& module) {
    // Visitor that goes over an AST and flags whether any node provides
    // code that needs compilation.
    struct VisitorModule : hilti::visitor::PreOrder<bool, VisitorModule> {
        explicit VisitorModule() = default;
        result_t operator()(const declaration::GlobalVariable& n, const_position_t p) { return true; }

        result_t operator()(const declaration::Function& n, const_position_t p) {
            return n.function().body() != std::nullopt;
        }
    };

    // Visitor that extracts all imported modules from an AST and sets their
    // requires-compilation flags.
    struct VisitorImports : hilti::visitor::PreOrder<void, VisitorImports> {
        explicit VisitorImports(std::shared_ptr<Context> ctx, const std::set<ID>& modules)
            : context(std::move(ctx)), modules(modules) {}
        std::shared_ptr<Context> context;
        const std::set<ID>& modules;

        void operator()(const declaration::ImportedModule& n, const_position_t p) {
            for ( const auto& i : p.node.scope()->items() ) {
                for ( const auto& m : i.second ) {
                    auto md = m->tryAs<declaration::Module>();
                    if ( ! md )
                        continue;

                    auto v = VisitorModule();
                    for ( auto i : v.walk(md->root()) ) {
                        if ( auto x = v.dispatch(i); ! (x && *x) )
                            continue;

                        if ( auto cached = context->lookupModule(n.id()) ) {
                            cached->requires_compilation = true;
                            context->updateModule(*cached);
                            break;
                        }
                    }
                }
            }
        }
    };

    // Run the visitors.
    auto v = VisitorImports(context(), _modules);
    for ( auto i : v.walk(module) )
        v.dispatch(i);
}

bool Unit::_validateASTs(std::vector<std::pair<ID, NodeRef>>& modules,
                         const std::function<bool(const ID&, NodeRef&)>& run_hooks_callback) {
    if ( options().skip_validation )
        return true;

    auto valid = true;

    for ( auto& [id, module] : modules ) {
        if ( ! _validateAST(id, NodeRef(module), run_hooks_callback) )
            valid = false;
    }

    return valid;
}

/**
 * Recursive helper function to traverse the AST and collect relevant errors.
 * We pick errors on child nodes first, and then hide any further ones
 * located in parents along the way. We take only the first error in each
 * priority class (normal & low). If a node doesn't have a location, we
 * substitute the closest parent location.
 *
 * @param n root node for validation
 * @param closest_location location closest to *n* on the path leading to it
 * @param errors errors recorded for reporting so far; function will extend this
 * @return two booleans with the 1st indicating if we have already found a
 * normal priroity error on the path, and the 2nd if we have already found a
 * low priority error on the path.
 */
static std::pair<bool, bool> _recursiveValidateAST(const Node& n, Location closest_location,
                                                   std::vector<node::Error>* errors) {
    auto have_normal = false;
    auto have_low = false;

    if ( n.location() )
        closest_location = n.location();

    for ( const auto& c : n.childs() ) {
        auto [normal, low] = _recursiveValidateAST(c, closest_location, errors);
        have_normal = (have_normal || normal);
        have_low = (have_low || low);
    }

    if ( have_normal )
        return std::make_pair(have_normal, have_low);

    if ( n.hasErrors() ) {
        for ( auto&& e : n.errors() ) {
            if ( ! e.location && closest_location )
                e.location = closest_location;

            if ( ! (have_normal || have_low) )
                errors->emplace_back(std::move(e));
        }

        for ( const auto& e : n.errors() ) {
            if ( e.priority == node::ErrorPriority::Normal )
                return std::make_pair(true, have_low);
            else
                return std::make_pair(have_normal, true);
        }
    }

    return std::make_pair(have_normal, have_low);
}

static void _reportErrors(const std::vector<node::Error>& errors) {
    // We skip any low-priority errors at first. Only if we have only those,
    // we will report them. We also generally suppress duplicates.
    std::set<node::Error> reported;

    auto report_one = [&](const auto& e) {
        if ( reported.find(e) == reported.end() ) {
            logger().error(e.message, e.context, e.location);
            reported.insert(e);
        }
    };

    for ( const auto& e : errors ) {
        if ( e.priority != node::ErrorPriority::Low )
            report_one(e);
    }

    if ( reported.size() )
        return;

    for ( const auto& e : errors ) {
        if ( e.priority == node::ErrorPriority::Low )
            report_one(e);
    }
}

bool Unit::_validateASTs(const ID& id, std::vector<Node>& nodes,
                         const std::function<bool(const ID&, std::vector<Node>&)>& run_hooks_callback) {
    if ( options().skip_validation )
        return true;

    if ( ! run_hooks_callback(id, nodes) )
        return false;

    std::vector<node::Error> errors;
    for ( auto& n : nodes )
        _recursiveValidateAST(n, Location(), &errors);

    if ( errors.empty() )
        return true;

    _reportErrors(errors);
    return false;
}

bool Unit::_validateAST(const ID& id, NodeRef module,
                        const std::function<bool(const ID&, NodeRef&)>& run_hooks_callback) {
    if ( options().skip_validation )
        return true;

    if ( ! run_hooks_callback(id, module) )
        return false;

    std::vector<node::Error> errors;
    _recursiveValidateAST(*module, Location(), &errors);

    if ( errors.empty() )
        return true;

    _reportErrors(errors);
    return false;
}

void Unit::_dumpAST(const Node& module, const logging::DebugStream& stream, const std::string& prefix, int round) {
    if ( ! logger().isEnabled(stream) )
        return;

    const auto& m = module.as<Module>();

    std::string r;

    if ( round > 0 )
        r = fmt(" (round %d)", round);

    HILTI_DEBUG(stream, fmt("# %s: %s%s", m.id(), prefix, r));
    detail::renderNode(module, stream, true);

    if ( m.preserved().size() ) {
        HILTI_DEBUG(stream, fmt("# %s: Preserved nodes%s", m.id(), r));
        for ( const auto& i : m.preserved() )
            detail::renderNode(i, stream, true);
    }
}

void Unit::_dumpASTs(const logging::DebugStream& stream, const std::string& prefix, int round) {
    if ( ! logger().isEnabled(stream) )
        return;

    for ( auto& [id, module] : _currentModules() )
        _dumpAST(*module, stream, prefix, round);
}

void Unit::_dumpAST(const Node& module, std::ostream& stream, const std::string& prefix, int round) {
    const auto& m = module.as<Module>();

    std::string r;

    if ( round > 0 )
        r = fmt(" (round %d)", round);

    stream << fmt("# %s: %s%s\n", m.id(), prefix, r);
    detail::renderNode(module, stream, true);

    if ( m.preserved().size() ) {
        stream << fmt("# %s: Preserved nodes%s\n", m.id(), r);
        for ( const auto& i : m.preserved() )
            detail::renderNode(i, stream, true);
    }
}

void Unit::_dumpASTs(std::ostream& stream, const std::string& prefix, int round) {
    for ( auto& [id, module] : _currentModules() )
        _dumpAST(*module, stream, prefix, round);
}

void Unit::_saveIterationASTs(const std::string& prefix, int round) {
    if ( ! logger().isEnabled(logging::debug::AstDumpIterations) )
        return;

    std::ofstream out(fmt("ast-%d.tmp", round));
    _dumpASTs(out, prefix, round);
}

Result<Unit> Unit::link(const std::shared_ptr<Context>& context, const std::vector<linker::MetaData>& mds) {
    HILTI_DEBUG(logging::debug::Compiler, fmt("linking %u modules", mds.size()));
    auto cxx_unit = detail::CodeGen(context).linkUnits(mds);

    if ( ! cxx_unit )
        return result::Error("no C++ code available for unit");

    return fromCXX(context, *cxx_unit, "<linker>");
}

std::pair<bool, std::optional<linker::MetaData>> Unit::readLinkerMetaData(std::istream& input,
                                                                          const hilti::rt::filesystem::path& path) {
    HILTI_DEBUG(logging::debug::Compiler, fmt("reading linker data from %s", path));
    return detail::cxx::Unit::readLinkerMetaData(input);
}

std::set<context::ModuleIndex> Unit::allImported(bool code_only) const {
    std::set<context::ModuleIndex> all;

    for ( const auto& m : _modules ) {
        auto cached = _lookupModule(m);
        assert(cached);

        if ( code_only && ! cached->requires_compilation )
            continue;

        all.insert(cached->index);
    }

    return all;
}

void Unit::_resetNodes(const ID& id, Node* root) {
    HILTI_DEBUG(logging::debug::Compiler, fmt("resetting nodes for module %s", id));

    for ( const auto&& i : hilti::visitor::PreOrder<>().walk(root) ) {
        i.node.clearCache();
        i.node.scope()->clear();
        i.node.clearErrors();
    }
}
