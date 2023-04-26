// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <fstream>
#include <utility>

#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/imported-module.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/node.h>
#include <hilti/base/visitor.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using namespace hilti::context;
using util::fmt;

namespace hilti::logging::debug {
inline const DebugStream AstCodegen("ast-codegen");
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug

std::unordered_map<ID, unsigned int> Unit::_uid_cache;

template<typename PluginMember, typename... Args>
bool runHook(bool* modified, const Plugin& plugin, const Node* module, const std::string& extension, PluginMember hook,
             const std::string& debug_msg, const Args&... args) {
    if ( ! (plugin.*hook) )
        return true;

    auto p = plugin::registry().pluginForExtension(extension);
    if ( ! p )
        logger().internalError(util::fmt("no plugin for unit extension %s: %s", extension, p.error()));

    if ( p->get().component != plugin.component )
        return true;

    auto msg = fmt("[%s] %s", plugin.component, debug_msg);

    HILTI_DEBUG(logging::debug::Compiler, msg);
    if ( (*(plugin.*hook))(args...) ) {
        *modified = true;
        HILTI_DEBUG(logging::debug::Compiler, "  -> modified");
    }

    return logger().errors() == 0;
}

ID Unit::_makeUniqueID(const ID& id) {
    if ( auto i = _uid_cache.find(id); i != _uid_cache.end() )
        return ID(util::fmt("%s_%s", id, ++(i->second)));
    else {
        _uid_cache[id] = 1;
        return id;
    }
}

Unit::~Unit() { _destroyModule(); }

Result<std::shared_ptr<Unit>> Unit::fromCache(const std::shared_ptr<Context>& context,
                                              const hilti::rt::filesystem::path& path, const std::optional<ID>& scope) {
    if ( auto cached = context->lookupUnit(path, scope) )
        return cached->unit;
    else
        return result::Error(fmt("unknown module %s", path));
}

Result<std::shared_ptr<Unit>> Unit::fromSource(const std::shared_ptr<Context>& context,
                                               const hilti::rt::filesystem::path& path, const std::optional<ID>& scope,
                                               std::optional<hilti::rt::filesystem::path> process_extension) {
    if ( auto cached = context->lookupUnit(path, scope, process_extension) )
        return cached->unit;

    auto module = _parse(context, path);
    if ( ! module )
        return module.error();

    if ( ! process_extension )
        process_extension = path.extension();

    auto id = module->id();
    auto unit = std::shared_ptr<Unit>(new Unit(context, id, scope, path, *process_extension,
                                               std::move(*module))); // no make_shared, ctor is private
    context->cacheUnit(unit);

    return unit;
}

std::shared_ptr<Unit> Unit::fromModule(const std::shared_ptr<Context>& context, const hilti::Module& module,
                                       hilti::rt::filesystem::path extension) {
    auto unit = std::shared_ptr<Unit>(new Unit(context, module.id(), {}, {}, std::move(extension),
                                               module)); // no make_shared, ctor is private
    context->cacheUnit(unit);
    return unit;
}

Result<std::shared_ptr<Unit>> Unit::fromImport(const std::shared_ptr<Context>& context, const ID& id,
                                               const hilti::rt::filesystem::path& parse_extension,
                                               const hilti::rt::filesystem::path& process_extension,
                                               std::optional<ID> scope,
                                               std::vector<hilti::rt::filesystem::path> search_dirs) {
    if ( auto cached = context->lookupUnit(id, scope, process_extension) )
        return cached->unit;

    auto parse_plugin = plugin::registry().pluginForExtension(parse_extension);

    if ( ! (parse_plugin && parse_plugin->get().parse) )
        return result::Error(fmt("no plugin provides support for importing *%s files", parse_extension.native()));

    auto name = fmt("%s%s", util::tolower(id), parse_extension.native());

    if ( scope )
        name = fmt("%s/%s", util::replace(scope->str(), ".", "/"), name);

    std::vector<hilti::rt::filesystem::path> library_paths = std::move(search_dirs);

    if ( parse_plugin->get().library_paths )
        library_paths = util::concat(std::move(library_paths), (*parse_plugin->get().library_paths)(context));

    library_paths = util::concat(context->options().library_paths, library_paths);

    auto path = util::findInPaths(name, library_paths);
    if ( ! path ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("Failed to find module '%s' in search paths:", name));
        for ( const auto& p : library_paths )
            HILTI_DEBUG(logging::debug::Compiler, fmt("  %s", p));

        return result::Error(fmt("cannot find file"));
    }

    auto unit = fromSource(context, *path, scope, process_extension);
    if ( ! unit )
        return unit;

    if ( (*unit)->id() != id )
        return result::Error(
            util::fmt("file %s does not contain expected module %s (but %s)", path->native(), id, (*unit)->id()));

    return unit;
}

Result<std::shared_ptr<Unit>> Unit::fromCXX(const std::shared_ptr<Context>& context, detail::cxx::Unit cxx,
                                            const hilti::rt::filesystem::path& path) {
    return std::shared_ptr<Unit>(
        new Unit(context, ID(fmt("<CXX/%s>", path.native())), {}, ".cxx", path, std::move(cxx)));
}

Result<hilti::Module> Unit::_parse(const std::shared_ptr<Context>& context, const hilti::rt::filesystem::path& path) {
    util::timing::Collector _("hilti/compiler/parser");

    std::ifstream in;
    in.open(path);

    if ( ! in )
        return result::Error(fmt("cannot open source file %s", path));

    auto plugin = plugin::registry().pluginForExtension(path.extension());

    if ( ! (plugin && plugin->get().parse) )
        return result::Error(fmt("no plugin provides support for importing *%s files", path.extension().native()));

    auto dbg_message = fmt("parsing file %s as %s code", path, plugin->get().component);

    if ( plugin->get().component != "HILTI" )
        dbg_message += fmt(" (%s)", plugin->get().component);

    HILTI_DEBUG(logging::debug::Compiler, dbg_message);

    auto node = (*plugin->get().parse)(in, path);
    if ( ! node )
        return node.error();

    const auto& module = node->as<hilti::Module>();
    if ( ! module.id() )
        return result::Error(fmt("module in %s does not have an ID", path.native()));

    return module;
}

Result<Nothing> Unit::buildASTScopes(const Plugin& plugin) {
    if ( ! _module )
        return Nothing();

    bool modified = false; // not used

    if ( ! runHook(&modified, plugin, &*_module, _extension, &Plugin::ast_build_scopes,
                   fmt("building scopes for module %s", uniqueID()), context(), &*_module, this) )
        return result::Error("errors encountered during scope building");

    return Nothing();
}

Result<Unit::ASTState> Unit::resolveAST(const Plugin& plugin) {
    bool modified = false;

    if ( ! runHook(&modified, plugin, &*_module, _extension, &Plugin::ast_normalize,
                   fmt("normalizing nodes in module %s", uniqueID()), context(), &*_module, this) )
        return result::Error("errors encountered during normalizing");

    if ( ! runHook(&modified, plugin, &*_module, _extension, &Plugin::ast_coerce,
                   fmt("coercing nodes in module %s", uniqueID()), context(), &*_module, this) )
        return result::Error("errors encountered during coercing");

    if ( ! runHook(&modified, plugin, &*_module, _extension, &Plugin::ast_resolve,
                   fmt("resolving nodes in module %s", uniqueID()), context(), &*_module, this) )
        return result::Error("errors encountered during resolving");

    return modified ? Modified : NotModified;
}

bool Unit::validateASTPre(const Plugin& plugin) {
    if ( ! _module )
        return true;

    bool modified = false; // not used
    runHook(&modified, plugin, &*_module, _extension, &Plugin::ast_validate_pre,
            fmt("validating module %s (pre)", uniqueID()), context(), &*_module, this);

    return _collectErrors();
}

bool Unit::validateASTPost(const Plugin& plugin) {
    if ( ! _module )
        return true;

    bool modified = false; // not used
    runHook(&modified, plugin, &*_module, _extension, &Plugin::ast_validate_post,
            fmt("validating module %s (post)", uniqueID()), context(), &*_module, this);

    return _collectErrors();
}

Result<Nothing> Unit::transformAST(const Plugin& plugin) {
    if ( ! _module )
        return Nothing();

    bool modified = false;
    runHook(&modified, plugin, &*_module, _extension, &Plugin::ast_transform, fmt("transforming module %s", uniqueID()),
            context(), &*_module, this);

    return Nothing();
}

Result<Nothing> Unit::codegen() {
    if ( ! _module )
        return Nothing();

    HILTI_DEBUG(logging::debug::Compiler, fmt("compiling module %s to C++", uniqueID()));
    logging::DebugPushIndent _(logging::debug::Compiler);

    // Compile to C++.
    auto c = detail::CodeGen(context()).compileModule(*_module, this, true);

    if ( logger().errors() )
        return result::Error("errors encountered during code generation");

    if ( ! c )
        logger().internalError(fmt("code generation for module %s failed, but did not log error (%s)", uniqueID(),
                                   c.error().description()));

    // Import declarations from our dependencies. They will have been compiled
    // at this point.
    //
    // TODO(robin): Would be nice if we had a "cheap" compilation mode that
    // only generated declarations.
    for ( const auto& unit : dependencies(true) ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("importing declarations from module %s", unit.lock()->uniqueID()));
        auto other = detail::CodeGen(context()).compileModule(unit.lock()->module(), unit.lock().get(), false);
        c->importDeclarations(*other);
    }

    HILTI_DEBUG(logging::debug::Compiler, fmt("finalizing module %s", uniqueID()));
    if ( auto x = c->finalize(); ! x )
        return x.error();

    _cxx_unit = *c;
    return Nothing();
}

Result<Nothing> Unit::print(std::ostream& out) const {
    if ( _module )
        detail::printAST(*_module, out);

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

void Unit::_recursiveDependencies(std::vector<std::weak_ptr<Unit>>* dst, std::unordered_set<const Unit*>* seen) const {
    // This uses two vectors because the weak_ptr are a bit tough to work with,
    // in particular they can't be compared through std::find().

    for ( const auto& d : _dependencies ) {
        auto dptr = d.lock().get();

        if ( seen->find(dptr) != seen->end() )
            continue;

        dst->push_back(d);
        seen->insert(dptr);
        dptr->_recursiveDependencies(dst, seen);
    }
}

std::vector<std::weak_ptr<Unit>> Unit::dependencies(bool recursive) const {
    if ( ! recursive )
        return _dependencies;

    std::vector<std::weak_ptr<Unit>> deps;
    std::unordered_set<const Unit*> seen;
    _recursiveDependencies(&deps, &seen);
    return deps;
}

bool Unit::addDependency(const std::shared_ptr<Unit>& unit) {
    for ( const auto& d : _dependencies ) {
        if ( d.lock().get() == unit.get() )
            return false;
    }

    _dependencies.push_back(unit);
    return true;
}

bool Unit::requiresCompilation() {
    if ( _requires_compilation )
        return true;

    // Visitor that goes over an AST and flags whether any node provides
    // code that needs compilation.
    struct Visitor : hilti::visitor::PreOrder<bool, Visitor> {
        explicit Visitor() = default;
        result_t operator()(const declaration::GlobalVariable& n, const_position_t p) { return true; }

        result_t operator()(const declaration::Function& n, const_position_t p) {
            return n.function().body() != std::nullopt;
        }
    };

    auto v = Visitor();
    for ( auto i : v.walk(*_module) ) {
        if ( auto rc = v.dispatch(i) ) {
            if ( rc && *rc )
                return true;
        }
    }

    return false;
}

static node::ErrorPriority _recursiveValidateAST(const Node& n, Location closest_location, node::ErrorPriority prio,
                                                 int level, std::vector<node::Error>* errors) {
    if ( n.location() )
        closest_location = n.location();

    if ( ! n.pruneWalk() ) {
        auto oprio = prio;
        for ( const auto& c : n.children() )
            prio = std::max(prio, _recursiveValidateAST(c, closest_location, oprio, level + 1, errors));
    }

    auto errs = n.errors();
    auto nprio = prio;
    for ( auto& err : errs ) {
        if ( ! err.location && closest_location )
            err.location = closest_location;

        if ( err.priority > prio )
            errors->push_back(err);

        nprio = std::max(nprio, err.priority);
    }

    return nprio;
}

static void _reportErrors(const std::vector<node::Error>& errors) {
    // We only report the highest priority error category.
    std::set<node::Error> reported;

    auto prios = {node::ErrorPriority::High, node::ErrorPriority::Normal, node::ErrorPriority::Low};

    for ( auto p : prios ) {
        for ( const auto& e : errors ) {
            if ( e.priority != p )
                continue;

            if ( reported.find(e) == reported.end() ) {
                logger().error(e.message, e.context, e.location);
                reported.insert(e);
            }
        }

        if ( reported.size() )
            break;
    }
}

bool Unit::_collectErrors() {
    std::vector<node::Error> errors;
    _recursiveValidateAST(*_module, Location(), node::ErrorPriority::NoError, 0, &errors);

    if ( errors.size() ) {
        _reportErrors(errors);
        return false;
    }

    return true;
}

void Unit::_destroyModule() {
    if ( ! _module )
        return;

    _module->as<Module>().destroyPreservedNodes();
    _module->destroyChildren();
    _module = {};
}

Result<std::shared_ptr<Unit>> Unit::link(const std::shared_ptr<Context>& context,
                                         const std::vector<linker::MetaData>& mds) {
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

void Unit::resetAST() {
    if ( ! _module )
        return;

    HILTI_DEBUG(logging::debug::Compiler, fmt("resetting nodes for module %s", uniqueID()));

    auto v = hilti::visitor::PreOrder<>();
    for ( auto&& i : v.walk(&*_module) ) {
        i.node.clearScope();
        i.node.clearErrors();
    }
}
