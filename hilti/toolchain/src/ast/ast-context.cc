// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/type.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/ast-dumper.h>
#include <hilti/compiler/detail/optimizer.h>
#include <hilti/compiler/detail/resolver.h>
#include <hilti/compiler/detail/scope-builder.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/type-unifier.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::util;

namespace hilti::logging::debug {
inline const DebugStream AstCodegen("ast-codegen");
inline const DebugStream AstDeclarations("ast-declarations");
inline const DebugStream AstDumpIterations("ast-dump-iterations");
inline const DebugStream AstFinal("ast-final");
inline const DebugStream AstStats("ast-stats");
inline const DebugStream AstOrig("ast-orig");
inline const DebugStream AstPrintTransformed("ast-print-transformed");
inline const DebugStream AstResolved("ast-resolved");
inline const DebugStream AstTransformed("ast-transformed");
inline const DebugStream Compiler("compiler");
inline const DebugStream Resolver("resolver");
} // namespace hilti::logging::debug

std::string ASTRoot::_dump() const { return ""; }

ASTContext::ASTContext(Context* context) : _context(context) {
    _root = ASTRoot::create(this);
    _root->getOrCreateScope();        // create the global scope
    _declarations_by_index.resize(1); // index 0 is reserved for null
    _types_by_index.resize(1);        // index 0 is reserved for null
}

ASTContext::~ASTContext() { _root->destroyChildren(); }

Result<declaration::module::UID> ASTContext::parseSource(Builder* builder, const hilti::rt::filesystem::path& path,
                                                         std::optional<hilti::rt::filesystem::path> process_extension) {
    return _parseSource(builder, path, {}, std::move(process_extension));
}

Result<declaration::module::UID> ASTContext::importModule(
    Builder* builder, const ID& id, const ID& scope, const hilti::rt::filesystem::path& parse_extension,
    const std::optional<hilti::rt::filesystem::path>& process_extension,
    std::vector<hilti::rt::filesystem::path> search_dirs) {
    // For compatibility with older versions, we allow import without reading a
    // file if we happen to know a module of that name already.
    if ( auto x = _modules_by_id_and_scope.find(std::make_pair(id, scope)); x != _modules_by_id_and_scope.end() )
        return x->second->uid();

    auto parse_plugin = plugin::registry().pluginForExtension(parse_extension);

    if ( ! (parse_plugin && parse_plugin->get().parse) )
        return result::Error(fmt("no plugin provides support for importing *%s files", parse_extension.native()));

    auto filename = fmt("%s%s", util::tolower(id), parse_extension.native());

    if ( scope )
        filename = fmt("%s/%s", util::replace(scope.str(), ".", "/"), filename);

    std::vector<hilti::rt::filesystem::path> library_paths = std::move(search_dirs);

    if ( parse_plugin->get().library_paths )
        library_paths = util::concat(std::move(library_paths), (*parse_plugin->get().library_paths)(_context));

    library_paths = util::concat(_context->options().library_paths, library_paths);

    auto path = util::findInPaths(filename, library_paths);
    if ( ! path ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("Failed to find module '%s' in search paths:", filename));
        for ( const auto& p : library_paths )
            HILTI_DEBUG(logging::debug::Compiler, fmt("  %s", p));

        return result::Error(fmt("cannot find file"));
    }

    if ( auto m = _modules_by_path.find(util::normalizePath(*path).native()); m != _modules_by_path.end() )
        return m->second->uid();

    auto uid = _parseSource(builder, *path, scope, process_extension);
    if ( ! uid )
        return uid;

    if ( uid->id != id )
        return result::Error(
            util::fmt("file %s does not contain expected module %s (but %s)", path->native(), id, uid->id));

    return uid;
}

std::shared_ptr<declaration::Module> ASTContext::newModule(Builder* builder, const ID& id,
                                                           const hilti::rt::filesystem::path& process_extension) {
    auto uid = declaration::module::UID(id, process_extension, process_extension);
    auto m = builder->declarationModule(uid);
    _addModuleToAST(m);
    return module(uid);
}

Result<declaration::module::UID> ASTContext::_parseSource(
    Builder* builder, const hilti::rt::filesystem::path& path, const ID& scope,
    std::optional<hilti::rt::filesystem::path> process_extension) {
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

    auto module = (*plugin->get().parse)(builder, in, path);
    if ( ! module )
        return module.error();

    if ( module && ! (*module)->id() )
        return result::Error(fmt("module in %s does not have an ID", path.native()));

    if ( scope )
        (*module)->setScopePath(scope);

    if ( process_extension ) {
        auto uid = (*module)->uid();
        uid.process_extension = *process_extension;
        (*module)->setUID(std::move(uid));
    }

    return _addModuleToAST(std::move(*module));
}

void ASTContext::updateModuleUID(const declaration::module::UID& old_uid, const declaration::module::UID& new_uid) {
    auto module = _modules_by_uid.find(old_uid);
    if ( module == _modules_by_uid.end() )
        logger().internalError("unknown module");

    module->second->setUID(new_uid);

    _modules_by_uid.erase(old_uid);
    _modules_by_path.erase(old_uid.path.native());
    _modules_by_id_and_scope.erase(std::make_pair(old_uid.id, module->second->scopePath()));

    _modules_by_uid[new_uid] = module->second;
    _modules_by_path[new_uid.path.native()] = module->second;
    _modules_by_id_and_scope[std::make_pair(new_uid.id, module->second->scopePath())] = module->second;
}

ast::DeclarationIndex ASTContext::register_(const DeclarationPtr& decl) {
    if ( auto index = decl->declarationIndex() )
        return index;

    auto index = ast::DeclarationIndex(_declarations_by_index.size());
    decl->setDeclarationIndex(index);
    _declarations_by_index.emplace_back(decl);

    if ( auto t = decl->tryAs<declaration::Type>() )
        t->type()->type()->setDeclarationIndex(index);

    if ( logger().isEnabled(logging::debug::Resolver) ) {
        std::string canon_id;

        if ( decl->canonicalID() )
            canon_id = decl->canonicalID().str() + std::string(" ");
        else
            canon_id = std::string("<no-canon-id> ");

        HILTI_DEBUG(logging::debug::Resolver, fmt("-> [%s] %s %s| %s (%s)", index, decl->typename_(), canon_id,
                                                  decl->print(), decl->location().dump(true)));
    }

    return index;
}

void ASTContext::replace(const Declaration* old, const DeclarationPtr& new_) {
    auto index = old->declarationIndex();
    if ( ! index )
        return;

    new_->setDeclarationIndex(index);
    _declarations_by_index[index.value()] = new_;

    if ( auto n = new_->tryAs<declaration::Type>() ) {
        auto o = old->tryAs<declaration::Type>();
        n->type()->type()->setDeclarationIndex(index);
        replace(o->type()->type().get(), n->type()->type());
    }

    if ( logger().isEnabled(logging::debug::Resolver) ) {
        std::string canon_id;

        if ( new_->canonicalID() )
            canon_id = new_->canonicalID().str() + std::string(" ");
        else
            canon_id = std::string("<no-canon-id> ");

        HILTI_DEBUG(logging::debug::Resolver, fmt("-> update: [%s] %s %s| %s (%s)", index, new_->typename_(), canon_id,
                                                  new_->print(), new_->location().dump(true)));
    }
}

DeclarationPtr ASTContext::lookup(ast::DeclarationIndex index) {
    if ( ! index || index.value() >= _declarations_by_index.size() )
        return nullptr;

    return _declarations_by_index.at(index.value());
}

ast::TypeIndex ASTContext::register_(const UnqualifiedTypePtr& type) {
    assert(! type->isWildcard());

    if ( auto index = type->typeIndex() )
        return index;

    auto index = ast::TypeIndex(_types_by_index.size());
    type->setTypeIndex(index);
    _types_by_index.emplace_back(type);

    if ( logger().isEnabled(logging::debug::Resolver) ) {
        std::string type_id;

        if ( type->typeID() )
            type_id = type->typeID().str() + std::string(" ");
        else
            type_id = std::string("<no-type-id> ");

        HILTI_DEBUG(logging::debug::Resolver, fmt("-> [%s] %s %s| %s (%s)", index, type->typename_(), type_id,
                                                  type->print(), type->location().dump(true)));
    }

    return index;
}

void ASTContext::replace(const UnqualifiedType* old, const UnqualifiedTypePtr& new_) {
    auto index = old->typeIndex();
    if ( ! index )
        return;

    new_->setTypeIndex(index);
    _types_by_index[index.value()] = new_;

    if ( logger().isEnabled(logging::debug::Resolver) ) {
        std::string type_id;

        if ( new_->typeID() )
            type_id = new_->typeID().str() + std::string(" ");
        else
            type_id = std::string("<no-type-id> ");

        HILTI_DEBUG(logging::debug::Resolver, fmt("-> update: [%s] %s %s| %s (%s)", index, new_->typename_(), type_id,
                                                  new_->print(), new_->location().dump(true)));
    }
}

UnqualifiedTypePtr ASTContext::lookup(ast::TypeIndex index) {
    if ( ! index || index.value() >= _types_by_index.size() )
        return nullptr;

    return _types_by_index.at(index.value());
}

declaration::module::UID ASTContext::_addModuleToAST(ModulePtr module) {
    assert(_modules_by_uid.find(module->uid()) == _modules_by_uid.end());
    assert(! module->hasParent()); // don't want to end up copying the whole AST
    auto uid = module->uid();

    _modules_by_uid[uid] = module;
    _modules_by_path[uid.path.native()] = module;
    _modules_by_id_and_scope[std::make_pair(uid.id, module->scopePath())] = module;

    _root->addChild(this, std::move(module));
    return uid;
}

template<typename PluginMember, typename... Args>
Result<Nothing> _runHook(const Plugin& plugin, PluginMember hook, const std::string& description, const Args&... args) {
    if ( ! (plugin.*hook) )
        return Nothing();

    auto msg = fmt("[%s] %s", plugin.component, description);

    HILTI_DEBUG(logging::debug::Compiler, msg);
    (*(plugin.*hook))(args...);

    if ( logger().errors() )
        return result::Error("aborting due to errors during " + description);

    return Nothing();
}

template<typename PluginMember, typename... Args>
Result<Nothing> _runHook(bool* modified, const Plugin& plugin, PluginMember hook, const std::string& description,
                         const Args&... args) {
    if ( ! (plugin.*hook) )
        return Nothing();

    auto msg = fmt("[%s] %s", plugin.component, description);

    HILTI_DEBUG(logging::debug::Compiler, msg);
    if ( (*(plugin.*hook))(args...) ) {
        *modified = true;
        HILTI_DEBUG(logging::debug::Compiler, "  -> modified");
    }

    if ( logger().errors() )
        return result::Error("aborting due to errors during " + description);

    return Nothing();
}

Result<Nothing> ASTContext::processAST(Builder* builder, Driver* driver) {
    if ( _resolved )
        return Nothing();

    _driver = driver;

    for ( const auto& plugin : plugin::registry().plugins() ) {
        if ( auto rc = _init(builder, plugin); ! rc )
            return rc;

        if ( auto rc = _validate(builder, plugin, true); ! rc )
            return rc;

        _driver->hookNewASTPreCompilation(plugin, _root);

        while ( true ) {
            if ( auto rc = _resolve(builder, plugin); ! rc )
                return rc;

            if ( _driver->hookNewASTPostCompilation(plugin, _root) ) {
                HILTI_DEBUG(logging::debug::Compiler, "  -> modified by driver plugin");
            }
            else
                break;
        }

        if ( auto rc = _validate(builder, plugin, false); ! rc )
            return rc;

        _checkAST(true);

        if ( auto rc = _transform(builder, plugin); ! rc )
            return rc;
    }

    if ( auto rc = driver->hookCompilationFinished(_root); ! rc )
        return rc;

    if ( _context->options().global_optimizations ) {
        if ( auto rc = _optimize(builder); ! rc )
            return rc;

        if ( auto rc = _validate(builder, plugin::registry().hiltiPlugin(), false); ! rc )
            return rc;
    }

    _driver = nullptr;
    return Nothing();
}

// Visitor double-checking that all declarations have their canonical IDs set.
struct VisitorCheckIDs : hilti::visitor::PreOrder {
    void operator()(Declaration* n) final {
        if ( ! n->canonicalID() ) {
            hilti::detail::ast_dumper::dump(std::cerr, n->parent()->as<Node>());
            logger().internalError(util::fmt("declaration without canonical ID found: %s", n->id()));
        }

        if ( ! n->fullyQualifiedID() ) {
            hilti::detail::ast_dumper::dump(std::cerr, n->parent()->as<Node>());
            logger().internalError(util::fmt("declaration without fully qualified ID found: %s", n->id()));
        }
    }
};

void ASTContext::_checkAST(bool finished) const {
#ifndef NDEBUG
    util::timing::Collector _("hilti/compiler/ast/check-ast");

    // Check parent pointering.
    for ( const auto& n : visitor::range(visitor::PreOrder(), _root, {}) ) {
        for ( const auto& c : n->children() ) {
            if ( c && c->parent() != n.get() )
                logger().internalError("broken parent pointer!");
        }
    }

    // Detect cycles, we shouldn't have them.
    std::set<Node*> seen = {};
    for ( const auto& n : visitor::range(visitor::PreOrder(), _root, {}) ) {
        if ( seen.find(n.get()) != seen.end() )
            logger().internalError("cycle in AST detected");

        seen.insert(n.get());
    }

    if ( finished )
        // Check that declaration IDs are are set.
        ::hilti::visitor::visit(VisitorCheckIDs(), root());
#endif
}

Result<Nothing> ASTContext::_init(Builder* builder, const Plugin& plugin) {
    _dumpAST(logging::debug::AstOrig, plugin, "Original AST", 0);

    return _runHook(plugin, &Plugin::ast_init, "initializing", builder, _root);
}

Result<Nothing> ASTContext::_clearState(Builder* builder, const Plugin& plugin) {
    util::timing::Collector _("hilti/compiler/ast/clear-state");

    for ( const auto& n : visitor::range(visitor::PreOrder(), _root, {}) ) {
        assert(n); // walk() should not give us null pointer children.
        n->clearErrors();
    }

    return Nothing();
}

Result<Nothing> ASTContext::_buildScopes(Builder* builder, const Plugin& plugin) {
    {
        util::timing::Collector _("hilti/compiler/ast/clear-scope");
        for ( const auto& n : visitor::range(visitor::PreOrder(), _root, {}) )
            n->clearScope();
    }

    bool modified;
    if ( auto rc = _runHook(&modified, plugin, &Plugin::ast_build_scopes, "building scopes", builder, _root); ! rc )
        return rc.error();

    return Nothing();
}

Result<Nothing> ASTContext::_resolveRoot(bool* modified, Builder* builder, const Plugin& plugin) {
    return _runHook(modified, plugin, &Plugin::ast_resolve, "resolving AST", builder, _root);
}

Result<Nothing> ASTContext::_resolve(Builder* builder, const Plugin& plugin) {
    HILTI_DEBUG(logging::debug::Compiler, fmt("resolving units with plugin %s", plugin.component))

    logging::DebugPushIndent _(logging::debug::Compiler);

    _total_rounds = 0;

    int round = 1;

    _saveIterationAST(plugin, "AST before first iteration", 0);

    while ( true ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("processing ASTs, round %d", round));
        logging::DebugPushIndent _(logging::debug::Compiler);

        ++_total_rounds;

        _checkAST(false);
        _clearState(builder, plugin);
        _buildScopes(builder, plugin);
        type_unifier::unify(builder, root());
        operator_::registry().initPending(builder);

        bool modified = false;
        if ( auto rc = _resolveRoot(&modified, builder, plugin); ! rc )
            return rc;

        _dumpAST(logging::debug::AstResolved, plugin, "AST after resolving", round);
        _saveIterationAST(plugin, "AST after resolving", round);

        if ( ! modified )
            break;

        if ( ++round >= 50 )
            logger().internalError("hilti::Unit::compile() didn't terminate, AST keeps changing");
    }

    _dumpAST(logging::debug::AstFinal, plugin, "Final AST", round);
    _dumpState(logging::debug::AstFinal);
    _dumpStats(logging::debug::AstStats, plugin);
    _dumpDeclarations(logging::debug::AstDeclarations, plugin);
    _saveIterationAST(plugin, "Final AST", round);

    _checkAST(false);

#ifndef NDEBUG
    // At this point, all built-in operators should be fully resolved. If not,
    // there's an internal problem somewhere. This will abort then.
    operator_::registry().debugEnforceBuiltInsAreResolved(builder);
#endif

    HILTI_DEBUG(logging::debug::Compiler, "finalized AST");
    _resolved = true;

    return Nothing();
}

Result<Nothing> ASTContext::_transform(Builder* builder, const Plugin& plugin) {
    if ( ! plugin.ast_transform )
        return Nothing();

    HILTI_DEBUG(logging::debug::Compiler, "transforming AST");

    bool modified = false;
    if ( auto rc = _runHook(&modified, plugin, &Plugin::ast_transform, "transforming", builder, _root); ! rc )
        return rc;

    _dumpAST(logging::debug::AstTransformed, plugin, "AST after transforming", 0);
    _dumpState(logging::debug::AstTransformed);
    _saveIterationAST(plugin, "AST after transforming");

    return Nothing();
}

Result<Nothing> ASTContext::_optimize(Builder* builder) {
    HILTI_DEBUG(logging::debug::Compiler, "performing global transformations");

    optimizer::optimize(builder, _root);

    // Make sure we didn't leave anything odd during optimization.
    _checkAST(true);

    return Nothing();
}

Result<Nothing> ASTContext::_validate(Builder* builder, const Plugin& plugin, bool pre_resolve) {
    if ( _context->options().skip_validation )
        return Nothing();

    bool modified = false; // not used

    if ( pre_resolve )
        _runHook(&modified, plugin, &Plugin::ast_validate_pre, "validating (pre)", builder, _root);
    else
        _runHook(&modified, plugin, &Plugin::ast_validate_post, "validating (post)", builder, _root);

    return _collectErrors();
}

void ASTContext::_dumpAST(const logging::DebugStream& stream, const Plugin& plugin, const std::string& prefix,
                          int round) {
    if ( ! logger().isEnabled(stream) )
        return;

    std::string r;

    if ( round > 0 )
        r = fmt(" (round %d)", round);

    HILTI_DEBUG(stream, fmt("# [%s] %s%s", plugin.component, prefix, r));
    ast_dumper::dump(stream, root(), true);
}

void ASTContext::_dumpAST(std::ostream& stream, const Plugin& plugin, const std::string& prefix, int round) {
    std::string r;

    if ( round > 0 )
        r = fmt(" (round %d)", round);

    stream << fmt("# [%s] %s%s\n", plugin.component, prefix, r);
    ast_dumper::dump(stream, root(), true);
}

void ASTContext::dump(const logging::DebugStream& stream, const std::string& prefix) {
    if ( ! logger().isEnabled(stream) )
        return;

    HILTI_DEBUG(stream, fmt("# %s\n", prefix));
    ast_dumper::dump(stream, root(), true);
}

void ASTContext::_dumpState(const logging::DebugStream& stream) {
    if ( ! logger().isEnabled(stream) )
        return;

    logger().debugSetIndent(stream, 0);
    HILTI_DEBUG(stream, "# State tables:");
    logger().debugPushIndent(stream);

    for ( auto idx = 1U; idx < _declarations_by_index.size(); idx++ ) {
        auto n = _declarations_by_index[idx];
        auto id = n->canonicalID() ? n->canonicalID() : ID("<no-canon-id>");
        HILTI_DEBUG(stream,
                    fmt("[%s] %s [%s] (%s)", ast::DeclarationIndex(idx), id, n->typename_(), n->location().dump(true)));
    }

    for ( auto idx = 1U; idx < _types_by_index.size(); idx++ ) {
        auto n = _types_by_index[idx];
        auto id = n->typeID() ? n->typeID() : ID("<no-type-id>");
        HILTI_DEBUG(stream,
                    fmt("[%s] %s [%s] (%s)", ast::TypeIndex(idx), id, n->typename_(), n->location().dump(true)));
    }

    logger().debugPopIndent(stream);
}

void ASTContext::_dumpStats(const logging::DebugStream& stream, const Plugin& plugin) {
    if ( ! logger().isEnabled(stream) )
        return;

    std::map<std::string, uint64_t> types;
    uint64_t total_nodes = 0;
    size_t depth = 0;

    for ( const auto& n : visitor::range(visitor::PreOrder(), root(), {}) ) {
        total_nodes++;
        types[n->typename_()]++;
        depth = std::max(depth, n->pathLength());
    }

    HILTI_DEBUG(stream, fmt("# [%s] AST statistics:", plugin.component));
    logger().debugPushIndent(stream);

    HILTI_DEBUG(stream, fmt("- max tree depth: %zu", depth));
    HILTI_DEBUG(stream, fmt("- # AST rounds %" PRIu64, _total_rounds));
    HILTI_DEBUG(stream, fmt("- # context declarations: %zu", _declarations_by_index.size()));
    HILTI_DEBUG(stream, fmt("- # context types: %zu", _types_by_index.size()));
    HILTI_DEBUG(stream, fmt("- # nodes: %" PRIu64, total_nodes));
    HILTI_DEBUG(stream, fmt("- # nodes > 1%%:"));

    logger().debugPushIndent(stream);
    for ( const auto& [type, num] : types ) {
        if ( static_cast<double>(num) / static_cast<double>(total_nodes) > 0.01 )
            HILTI_DEBUG(stream, fmt("- %s: %" PRIu64, type, num));
    }
    logger().debugPopIndent(stream);

    logger().debugPopIndent(stream);
}

void ASTContext::_dumpDeclarations(const logging::DebugStream& stream, const Plugin& plugin) {
    if ( ! logger().isEnabled(stream) )
        return;

    HILTI_DEBUG(stream, fmt("# [%s]", plugin.component));

    auto nodes = visitor::range(visitor::PreOrder(), _root, {});
    for ( auto i = nodes.begin(); i != nodes.end(); ++i ) {
        auto decl = (*i)->tryAs<Declaration>();
        if ( ! decl )
            continue;

        logger().debugSetIndent(stream, i.depth() - 1);
        HILTI_DEBUG(stream, fmt("- %s \"%s\" (%s)", ID((*i)->typename_()).local(), decl->id(), decl->canonicalID()));
    }

    logger().debugSetIndent(stream, 0);
}

void ASTContext::_saveIterationAST(const Plugin& plugin, const std::string& prefix, int round) {
    if ( ! logger().isEnabled(logging::debug::AstDumpIterations) )
        return;

    std::ofstream out(fmt("ast-%s-%d.tmp", plugin.component, round));
    _dumpAST(out, plugin, prefix, round);
}

void ASTContext::_saveIterationAST(const Plugin& plugin, const std::string& prefix, const std::string& tag) {
    if ( ! logger().isEnabled(logging::debug::AstDumpIterations) )
        return;

    std::ofstream out(fmt("ast-%s-%s.tmp", plugin.component, tag));
    _dumpAST(out, plugin, prefix, 0);
}

static void _recursiveDependencies(const ASTContext* ctx, const ModulePtr& module,
                                   std::vector<declaration::module::UID>* seen) {
    if ( std::find(seen->begin(), seen->end(), module->uid()) != seen->end() )
        return;

    for ( const auto& uid : module->dependencies() ) {
        seen->push_back(uid);
        auto dep = ctx->module(uid);
        assert(dep);
        _recursiveDependencies(ctx, dep, seen);
    }
}

std::vector<declaration::module::UID> ASTContext::dependencies(const declaration::module::UID& uid,
                                                               bool recursive) const {
    auto m = module(uid);
    assert(m);

    if ( recursive ) {
        std::vector<declaration::module::UID> seen;
        _recursiveDependencies(this, m, &seen);
        return seen;
    }
    else
        return m->dependencies();
}

static node::ErrorPriority _recursiveValidateAST(const NodePtr& n, Location closest_location, node::ErrorPriority prio,
                                                 int level, std::vector<node::Error>* errors) {
    if ( n->location() )
        closest_location = n->location();

    auto oprio = prio;
    for ( const auto& c : n->children() ) {
        if ( c )
            prio = std::max(prio, _recursiveValidateAST(c, closest_location, oprio, level + 1, errors));
    }

    auto errs = n->errors();
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

Result<Nothing> ASTContext::_collectErrors() {
    std::vector<node::Error> errors;
    _recursiveValidateAST(_root, Location(), node::ErrorPriority::NoError, 0, &errors);

    if ( errors.size() ) {
        _reportErrors(errors);
        return result::Error("validation failed");
    }

    return Nothing();
}
