// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

// Our uses of `visitor::range` below trigger false positives from >=gcc-13's
// dangling-reference check, see //
// https://gcc.gnu.org/bugzilla/show_bug.cgi?id=107532. Disable the warning for
// now.
#if __GNUC__ >= 13
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdangling-reference"
#endif

#include <ranges>
#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/type.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/ast-dumper.h>
#include <hilti/compiler/detail/cfg.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
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
inline const DebugStream AstResolved("ast-resolved");
inline const DebugStream AstTransformed("ast-transformed");
inline const DebugStream Compiler("compiler");
inline const DebugStream Resolver("resolver");
inline const DebugStream CfgInitial("cfg-initial");
inline const DebugStream CfgFinal("cfg-final");

} // namespace hilti::logging::debug

namespace hilti::ast::detail {

bool DeclarationPtrCmp::operator()(const Declaration* a, const Declaration* b) const {
    return a->canonicalID() < b->canonicalID();
}

// Visitor computing global declaration dependencies.
class DependencyTracker : hilti::visitor::PreOrder {
public:
    DependencyTracker(ASTContext* context) : context(context) {}

    // Entry point for computing all of an AST's global dependencies.
    void computeAllDependencies(ASTRoot* root);

    // Returns recorded dependencies for a given global declaration.
    // Returns an empty set if the given declaration is not known as having any
    // dependencies.
    const ASTContext::DeclarationSet& dependentDeclarations(Declaration* n);

    ASTContext* context;

    // State maintained while computing a single declaration's dependencies.
    int64_t level = 0;                 // recursion depth, zero is the starting declaration
    node::CycleDetector cd;            // state to detect dependency cycles
    ASTContext::DeclarationSet result; // receives the result of a single dependency computation

    // Records discovered dependencies. If a vector contains the index itself,
    // that means a cyclic dependency. We use vectors as values so that we can
    // maintain a deterministic order despite the pointers.
    std::map<const Declaration*, ASTContext::DeclarationSet, DeclarationPtrCmp> dependencies;

    // Compute and store the dependencies of a single declaration. Backend for
    // computeAllDependencies().
    void computeSingleDependency(Declaration* d);

    // Add a single dependency to the current result set if it's deemed of
    // interest.
    void insert(Declaration* d) {
        if ( level > 0                 // skip starting node of traversal
             && d->pathLength() <= 2 ) // global declarations only
            result.insert(d);
    }

    // Recursively trace all children of a given node for further
    // dependencies.
    void follow(Node* d) {
        if ( cd.haveSeen(d) )
            return;

        cd.recordSeen(d);

        ++level;
        for ( auto* child : d->children() ) {
            for ( auto* n : visitor::range(hilti::visitor::PreOrder(), child) )
                if ( n )
                    dispatch(n);
        }
        --level;

        dispatch(d);
    }

    void operator()(declaration::Constant* n) final {
        if ( auto* t = n->type()->type()->tryAs<type::Enum>() )
            // Special-case: For enum constants, insert a dependency on the
            // enum type instead, because that's the one that will declare it.
            insert(t->typeDeclaration());
        else
            insert(n);
    }

    void operator()(declaration::Function* n) final {
        insert(n);

        if ( auto decl_index = n->linkedDeclarationIndex() ) {
            // Insert dependency on the linked type's declaration.
            auto* decl = context->lookup(decl_index);
            insert(decl);
            follow(decl);
        }
    }

    void operator()(declaration::GlobalVariable* n) final { insert(n); }

    void operator()(declaration::Module* n) final { insert(n); }

    void operator()(declaration::Type* n) final { insert(n); }

    void operator()(QualifiedType* n) final {
        if ( n->isExternal() )
            follow(n->type());
    }

    void operator()(expression::Name* n) final {
        if ( auto* d = n->resolvedDeclaration() ) {
            dispatch(d);
            follow(d);
        }
    }

    void operator()(type::Name* n) final {
        if ( auto* d = n->resolvedDeclaration() ) {
            dispatch(d);
            follow(d);
        }
    }
};

void DependencyTracker::computeAllDependencies(ASTRoot* root) {
    for ( auto* module : root->childrenOfType<Declaration>() ) {
        computeSingleDependency(module);

        for ( auto* d : module->childrenOfType<Declaration>() )
            computeSingleDependency(d->as<Declaration>());
    }

    if ( logger().isEnabled(logging::debug::AstDeclarations) ) {
        HILTI_DEBUG(logging::debug::AstDeclarations, "Declaration dependencies:");

        for ( const auto& [decl, deps] : dependencies ) {
            if ( deps.empty() )
                continue;

            auto decl_ = fmt("[%s] %s", decl->displayName(), decl->canonicalID());
            auto deps_ = util::join(deps | std::views::transform([](const auto* d) { return d->canonicalID(); }), ", ");
            HILTI_DEBUG(logging::debug::AstDeclarations, fmt("- %s -> %s", decl_, deps_));
        }
    }
}

void DependencyTracker::computeSingleDependency(Declaration* d) {
    assert(d && d->pathLength() <= 2); // global declarations only
    assert(level == 0); // assure we aren't calling this method recursively; that's what follow() is for instead

    if ( dependencies.contains(d) )
        // Dependencies are already fully computed.
        return;

    cd.clear();
    result.clear();
    follow(d);
    assert(level == 0);

    if ( auto* t = d->tryAs<declaration::Type>(); t && t->type()->type()->isA<type::Enum>() )
        // Special-case: For enum types, remove the type itself from the
        // set. It will have gotten in there because we're special-casing
        // enum constants to insert the type instead. However, an enum type
        // can never be cyclic, so we don't want it in there.
        result.erase(d);

    dependencies.emplace(d, std::move(result));
}

const ASTContext::DeclarationSet& DependencyTracker::dependentDeclarations(Declaration* n) {
    if ( auto x = dependencies.find(n); x != dependencies.end() )
        return x->second;
    else {
        static const ASTContext::DeclarationSet empty;
        return empty;
    }
}

} // namespace hilti::ast::detail

std::string ASTRoot::_dump() const { return ""; }

ASTContext::ASTContext(Context* context) : _context(context) {
    _root = ASTRoot::create(this);
    _root->getOrCreateScope();        // create the global scope
    _declarations_by_index.resize(1); // index 0 is reserved for null
    _types_by_index.resize(1);        // index 0 is reserved for null
}

ASTContext::~ASTContext() {
    try {
        clear();

#ifndef NDEBUG
        if ( auto live = _nodes.size() )
            logger().internalError(util::fmt("AST still has %" PRIu64 " live nodes at context destruction!", live));
#endif
    } catch ( const std::exception& e ) {
        logger().internalError(util::fmt("unexpected exception in ~ASTContext: %s", e.what()));
    }
}

void ASTContext::clear() {
    _root.reset();

    _declarations_by_index.clear();
    _types_by_index.clear();
    _modules_by_uid.clear();
    _modules_by_path.clear();
    _modules_by_id_and_scope.clear();

    operator_::registry().clear(); // make sure there are no operators left using any of our nodes, because their
                                   // storage will go away

    garbageCollect();

    // We may have some live node left here if there are any external;y
    // retained pointers around still.
}

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

declaration::Module* ASTContext::newModule(Builder* builder, ID id,
                                           const hilti::rt::filesystem::path& process_extension) {
    auto uid = declaration::module::UID(std::move(id), process_extension, process_extension);
    auto* m = builder->declarationModule(uid);
    _addModuleToAST(m);
    return module(uid);
}

void ASTContext::garbageCollect() {
    hilti::util::timing::Collector _("hilti/compiler/ast/garbage-collector");

    // We're compacting the node array until all non-retained nodes are gone.

    std::vector<std::unique_ptr<Node>> new_nodes;

    size_t collected = 0;
    size_t retained = 0;

    bool changed;
    unsigned int rounds = 0;
    do {
        ++rounds;
        retained = 0;
        new_nodes.reserve(_nodes.size()); // NOLINT -- This can trigger various use-after-move warnings
        changed = false;

        for ( auto& n : _nodes ) {
            assert(n);

            if ( n->isRetained() ) {
                ++retained;
                new_nodes.emplace_back(std::move(n));
            }
            else {
                changed = true;
                ++collected;
                n.reset();
            }
        }

        _nodes = std::move(new_nodes);
    } while ( changed );

    HILTI_DEBUG(logging::debug::AstStats, util::fmt("garbage collected %zu nodes in %u round%s, %zu left retained",
                                                    collected, rounds, (rounds != 1 ? "s" : ""), retained));
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

    return _addModuleToAST(*module);
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

ast::DeclarationIndex ASTContext::register_(Declaration* decl) {
    if ( auto index = decl->declarationIndex() )
        return index;

    auto index = ast::DeclarationIndex(static_cast<uint32_t>(_declarations_by_index.size()));
    _declarations_by_index.emplace_back(decl);
    decl->setDeclarationIndex(index);

    if ( auto* t = decl->tryAs<declaration::Type>() )
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

void ASTContext::replace(Declaration* old, Declaration* new_) {
    auto index = old->declarationIndex();
    if ( ! index )
        return;

    _declarations_by_index[index.value()] = new_;
    new_->setDeclarationIndex(index);

    auto* n = new_->tryAs<declaration::Type>();
    auto* o = old->tryAs<declaration::Type>();
    if ( n && o ) {
        n->type()->type()->setDeclarationIndex(index);
        replace(o->type()->type(), n->type()->type());
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

Declaration* ASTContext::lookup(ast::DeclarationIndex index) {
    if ( ! index || index.value() >= _declarations_by_index.size() )
        return nullptr;

    return _declarations_by_index.at(index.value());
}

ast::TypeIndex ASTContext::register_(UnqualifiedType* type) {
    assert(! type->isWildcard());

    if ( auto index = type->typeIndex() )
        return index;

    auto index = ast::TypeIndex(static_cast<uint32_t>(_types_by_index.size()));
    _types_by_index.emplace_back(type);
    type->setTypeIndex(index);

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

void ASTContext::replace(UnqualifiedType* old, UnqualifiedType* new_) {
    auto index = old->typeIndex();
    if ( ! index )
        return;

    _types_by_index[index.value()] = new_;
    new_->setTypeIndex(index);

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

UnqualifiedType* ASTContext::lookup(ast::TypeIndex index) {
    if ( ! index || index.value() >= _types_by_index.size() )
        return nullptr;

    return _types_by_index.at(index.value());
}

declaration::module::UID ASTContext::_addModuleToAST(declaration::Module* module) {
    assert(! _modules_by_uid.contains(module->uid()));
    assert(! module->hasParent()); // don't want to end up copying the whole AST
    auto uid = module->uid();

    _modules_by_uid[uid] = module;
    _modules_by_path[uid.path.native()] = module;
    _modules_by_id_and_scope[std::make_pair(uid.id, module->scopePath())] = module;

    _root->addChild(this, module);
    return uid;
}

template<typename PluginMember, typename... Args>
static Result<Nothing> runHook(const Plugin& plugin, PluginMember hook, const std::string& description,
                               const Args&... args) {
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
static Result<Nothing> runHook(bool* modified, const Plugin& plugin, PluginMember hook, const std::string& description,
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
    auto _guard = scope_exit([&]() {
        const auto& hilti_plugin = plugin::registry().hiltiPlugin();
        _dumpAST(logging::debug::AstFinal, hilti_plugin, "Final AST", {});
        _dumpState(logging::debug::AstFinal);
        _dumpStats(logging::debug::AstStats, hilti_plugin.component);
    });

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

#ifndef NDEBUG
        checkAST(true);
#endif

        if ( plugin.ast_transform ) {
            // Make dependencies available for transformations.
            if ( auto rc = _computeDependencies(); ! rc )
                return rc;

            if ( auto rc = _transform(builder, plugin); ! rc )
                return rc;
        }
    }

    if ( auto rc = driver->hookCompilationFinished(_root); ! rc )
        return rc;

    if ( _context->options().global_optimizations ) {
        if ( auto rc = _optimize(builder); ! rc )
            return rc;

        if ( auto rc = _validate(builder, plugin::registry().hiltiPlugin(), false); ! rc )
            return rc;
    }

    HILTI_DEBUG(logging::debug::Compiler, "finalized AST");

    if ( auto rc = _computeDependencies(); ! rc )
        return rc;

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
    }
};

#ifndef NDEBUG
void ASTContext::checkAST(bool finished) const {
    util::timing::Collector _("hilti/compiler/ast/check-ast");

    // Check parent pointering.
    for ( const auto& n : visitor::range(visitor::PreOrder(), _root.get(), {}) ) {
        for ( const auto& c : n->children() ) {
            if ( c && c->parent() != n )
                logger().internalError("broken parent pointer!");
        }
    }

    // Detect cycles, we shouldn't have them.
    std::set<Node*> seen = {};
    for ( const auto& n : visitor::range(visitor::PreOrder(), _root.get(), {}) ) {
        if ( seen.contains(n) )
            logger().internalError("cycle in AST detected");

        seen.insert(n);
    }

    if ( finished )
        // Check that declaration IDs are set.
        ::hilti::visitor::visit(VisitorCheckIDs(), root());
}
#endif

Result<Nothing> ASTContext::_init(Builder* builder, const Plugin& plugin) {
    _dumpAST(logging::debug::AstOrig, plugin, "Original AST", 0);
    _dependency_tracker.reset(); // flush state
    return runHook(plugin, &Plugin::ast_init, "initializing", builder, _root);
}

void ASTContext::clearErrors(Node* node) {
    util::timing::Collector _("hilti/compiler/ast/clear-errors");

    for ( const auto& n : visitor::range(visitor::PreOrder(), (node ? node : root()), {}) ) {
        assert(n); // walk() should not give us null pointer children.
        n->clearErrors();
    }
}

void ASTContext::clearScopes(Node* node) {
    util::timing::Collector _("hilti/compiler/ast/clear-scope");

    for ( const auto& n : visitor::range(visitor::PreOrder(), (node ? node : root()), {}) )
        n->clearScope();
}

Result<Nothing> ASTContext::_buildScopes(Builder* builder, const Plugin& plugin) {
    bool modified;
    if ( auto rc = runHook(&modified, plugin, &Plugin::ast_build_scopes, "building scopes", builder, _root); ! rc )
        return rc.error();

    return Nothing();
}

Result<Nothing> ASTContext::_resolveRoot(bool* modified, Builder* builder, const Plugin& plugin) {
    return runHook(modified, plugin, &Plugin::ast_resolve, "resolving AST", builder, _root);
}

Result<Nothing> ASTContext::_resolve(Builder* builder, const Plugin& plugin) {
    HILTI_DEBUG(logging::debug::Compiler, fmt("resolving units with plugin %s", plugin.component))

    logging::DebugPushIndent _(logging::debug::Compiler);

    unsigned int round = 1;

    _saveIterationAST(plugin, "AST before first iteration", 0);

    while ( true ) {
        HILTI_DEBUG(logging::debug::Compiler, fmt("processing ASTs, round %u", round));
        logging::DebugPushIndent _(logging::debug::Compiler);

        ++_total_rounds;

#ifndef NDEBUG
        checkAST(false);
#endif

        clearErrors();
        clearScopes();
        _buildScopes(builder, plugin);
        type_unifier::unify(builder, root());
        operator_::registry().initPending(builder);

        bool modified = false;
        if ( auto rc = _resolveRoot(&modified, builder, plugin); ! rc )
            return rc;

        garbageCollect();

        _saveIterationAST(plugin, "AST after resolving", round);

        if ( ! modified )
            break;

        if ( ++round >= ASTContext::MaxASTIterationRounds )
            logger().internalError("hilti::Unit::compile() didn't terminate, AST keeps changing");
    }

    _dumpAST(logging::debug::AstResolved, plugin, "AST after resolving", _total_rounds);
    _dumpStats(logging::debug::AstStats, plugin.component);
    _dumpDeclarations(logging::debug::AstDeclarations, plugin);

#ifndef NDEBUG
    checkAST(false);
#endif

#ifndef NDEBUG
    // At this point, all built-in operators should be fully resolved. If not,
    // there's an internal problem somewhere. This will abort then.
    operator_::registry().debugEnforceBuiltInsAreResolved(builder);
#endif

    _resolved = true;
    _total_rounds = 0;

    return Nothing();
}

Result<Nothing> ASTContext::_transform(Builder* builder, const Plugin& plugin) {
    if ( ! plugin.ast_transform )
        return Nothing();

    HILTI_DEBUG(logging::debug::Compiler, "transforming AST");

    bool modified = false;
    if ( auto rc = runHook(&modified, plugin, &Plugin::ast_transform, "transforming", builder, _root); ! rc )
        return rc;

    _dumpAST(logging::debug::AstTransformed, plugin, "AST after transforming", 0);
    _dumpState(logging::debug::AstTransformed);
    _saveIterationAST(plugin, "AST after transforming");

    return Nothing();
}

Result<Nothing> ASTContext::_optimize(Builder* builder) {
    if ( logger().isEnabled(logging::debug::CfgInitial) )
        cfg::dump(logging::debug::CfgInitial, _root);

    HILTI_DEBUG(logging::debug::Compiler, "performing global transformations");

    if ( auto rc = Optimizer(builder).run(); ! rc )
        return rc;

    if ( logger().isEnabled(logging::debug::CfgFinal) )
        cfg::dump(logging::debug::CfgFinal, _root);

    return Nothing();
}

Result<Nothing> ASTContext::_validate(Builder* builder, const Plugin& plugin, bool pre_resolve) {
    if ( _context->options().skip_validation )
        return Nothing();

    bool modified = false; // not used

    if ( pre_resolve )
        runHook(&modified, plugin, &Plugin::ast_validate_pre, "validating (pre)", builder, _root);
    else
        runHook(&modified, plugin, &Plugin::ast_validate_post, "validating (post)", builder, _root);

    return collectErrors();
}

Result<Nothing> ASTContext::_computeDependencies() {
    util::timing::Collector _("hilti/compiler/ast/compute-dependencies");
    HILTI_DEBUG(logging::debug::Compiler, "computing AST dependencies");

    _dependency_tracker = std::make_unique<ast::detail::DependencyTracker>(this);
    _dependency_tracker->computeAllDependencies(_root.get());
    return Nothing();
}

void ASTContext::_dumpAST(const logging::DebugStream& stream, const Plugin& plugin, const std::string& prefix,
                          std::optional<unsigned int> round) {
    if ( ! logger().isEnabled(stream) )
        return;

    std::string r;

    if ( round )
        r = fmt(" (round %u)", *round);

    HILTI_DEBUG(stream, fmt("# [%s] %s%s", plugin.component, prefix, r));
    ast_dumper::dump(stream, root(), true);
}

void ASTContext::_dumpAST(std::ostream& stream, const Plugin& plugin, const std::string& prefix,
                          std::optional<unsigned int> round) {
    std::string r;

    if ( round )
        r = fmt(" (round %u)", *round);

    stream << fmt("# [%s] %s%s\n", plugin.component, prefix, r);
    ast_dumper::dump(stream, root(), true);
}

void ASTContext::dump(const logging::DebugStream& stream, const std::string& prefix) const {
    if ( ! logger().isEnabled(stream) )
        return;

    HILTI_DEBUG(stream, fmt("# %s\n", prefix));
    ast_dumper::dump(stream, root(), true);
}

void ASTContext::dump(std::ostream& out, bool include_state) const {
    ast_dumper::dump(out, root(), true);

    if ( include_state )
        _dumpState(out);
}

void ASTContext::_dumpState(const logging::DebugStream& stream) const {
    if ( ! logger().isEnabled(stream) )
        return;

    logger().debugSetIndent(stream, 0);
    HILTI_DEBUG(stream, "# State tables:");
    logger().debugPushIndent(stream);

    for ( auto idx = 1U; idx < _declarations_by_index.size(); idx++ ) {
        auto n = _declarations_by_index[idx];
        assert(n->isRetained());

        auto id = n->canonicalID() ? n->canonicalID() : ID("<no-canon-id>");
        HILTI_DEBUG(stream,
                    fmt("[%s] %s [%s] (%s)", ast::DeclarationIndex(idx), id, n->typename_(), n->location().dump(true)));
    }

    for ( auto idx = 1U; idx < _types_by_index.size(); idx++ ) {
        auto n = _types_by_index[idx];
        assert(n->isRetained());

        const auto& id = n->typeID() ? n->typeID() : ID("<no-type-id>");
        HILTI_DEBUG(stream,
                    fmt("[%s] %s [%s] (%s)", ast::TypeIndex(idx), id, n->typename_(), n->location().dump(true)));
    }

    logger().debugPopIndent(stream);
}

void ASTContext::_dumpState(std::ostream& out) const {
    // This mostly duplicates the code from above but for ostreams. Not clear
    // how to nicely cover both cases with just one version of the code.
    out << "\n# State tables:\n\n";

    for ( auto idx = 1U; idx < _declarations_by_index.size(); idx++ ) {
        auto n = _declarations_by_index[idx];
        assert(n->isRetained());

        auto id = n->canonicalID() ? n->canonicalID() : ID("<no-canon-id>");
        out << fmt("  [%s] %s [%s] (%s)\n", ast::DeclarationIndex(idx), id, n->typename_(), n->location().dump(true));
    }

    for ( auto idx = 1U; idx < _types_by_index.size(); idx++ ) {
        auto n = _types_by_index[idx];
        assert(n->isRetained());

        const auto& id = n->typeID() ? n->typeID() : ID("<no-type-id>");
        out << fmt("  [%s] %s [%s] (%s)", ast::TypeIndex(idx), id, n->typename_(), n->location().dump(true));
    }
}

void ASTContext::_dumpStats(const logging::DebugStream& stream, std::string_view tag) {
    if ( ! logger().isEnabled(stream) )
        return;

    size_t depth = 0;
    uint64_t reachable = 0;

    for ( const auto& n : visitor::range(visitor::PreOrder(), root(), {}) ) {
        depth = std::max(depth, n->pathLength());
        reachable++;
    }

    uint64_t retained = 0;
    uint64_t live = 0;
    std::map<std::string, uint64_t> live_by_type;

    for ( const auto& n : _nodes ) {
        ++live;
        live_by_type[n->typename_()]++;

        if ( n->isRetained() )
            ++retained;
    }

    HILTI_DEBUG(stream, fmt("# [%s] AST statistics:", tag));
    logger().debugPushIndent(stream);

    if ( _total_rounds )
        HILTI_DEBUG(stream, fmt("- # AST rounds %u", _total_rounds));

    HILTI_DEBUG(stream, fmt("- max tree depth: %zu", depth));
    HILTI_DEBUG(stream, fmt("- # context declarations: %zu", _declarations_by_index.size()));
    HILTI_DEBUG(stream, fmt("- # context types: %zu", _types_by_index.size()));
    HILTI_DEBUG(stream, fmt("- # context modules: %zu", _modules_by_uid.size()));
    HILTI_DEBUG(stream, fmt("- # nodes reachable in AST: %" PRIu64, reachable));
    HILTI_DEBUG(stream, fmt("- # nodes live: %" PRIu64, live));
    HILTI_DEBUG(stream, fmt("- # nodes retained: %" PRIu64, retained));
    HILTI_DEBUG(stream, fmt("- # nodes live > 1%%:"));

    logger().debugPushIndent(stream);
    for ( const auto& [type, num] : live_by_type ) {
        if ( live != 0 && static_cast<double>(num) / static_cast<double>(live) > 0.01 )
            HILTI_DEBUG(stream, fmt("- %s: %" PRIu64, type, num));
    }
    logger().debugPopIndent(stream);

    logger().debugPopIndent(stream);
}

void ASTContext::_dumpDeclarations(const logging::DebugStream& stream, const Plugin& plugin) {
    if ( ! logger().isEnabled(stream) )
        return;

    HILTI_DEBUG(stream, fmt("# [%s]", plugin.component));

    auto nodes = visitor::range(visitor::PreOrder(), _root.get(), {});
    for ( auto i = nodes.begin(); i != nodes.end(); ++i ) {
        auto* decl = (*i)->tryAs<Declaration>();
        if ( ! decl )
            continue;

        logger().debugSetIndent(stream, i.depth() - 1);
        HILTI_DEBUG(stream, fmt("- %s \"%s\" (%s)", ID((*i)->typename_()).local(), decl->id(), decl->canonicalID()));
    }

    logger().debugSetIndent(stream, 0);
}

void ASTContext::_saveIterationAST(const Plugin& plugin, const std::string& prefix, unsigned int round) {
    if ( ! logger().isEnabled(logging::debug::AstDumpIterations) )
        return;

    std::ofstream out(fmt("ast-%s-%u.tmp", plugin.component, round));
    _dumpAST(out, plugin, prefix, round);
}

void ASTContext::_saveIterationAST(const Plugin& plugin, const std::string& prefix, const std::string& tag) {
    if ( ! logger().isEnabled(logging::debug::AstDumpIterations) )
        return;

    std::ofstream out(fmt("ast-%s-%s.tmp", plugin.component, tag));
    _dumpAST(out, plugin, prefix, 0);
}

const ASTContext::DeclarationSet& ASTContext::dependentDeclarations(Declaration* n) {
    if ( _dependency_tracker )
        return _dependency_tracker->dependentDeclarations(n);
    else
        logger().internalError("dependencies not computed yet");
}

static node::ErrorPriority recursiveValidateAST(Node* n, Location closest_location, node::ErrorPriority prio, int level,
                                                std::vector<node::Error>* errors) {
    if ( n->location() )
        closest_location = n->location();

    auto oprio = prio;
    for ( const auto& c : n->children() ) {
        if ( c )
            prio = std::max(prio, recursiveValidateAST(c, closest_location, oprio, level + 1, errors));
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

static void reportErrors(const std::vector<node::Error>& errors) {
    // We only report the highest priority error category.
    std::set<node::Error> reported;

    auto prios = {node::ErrorPriority::High, node::ErrorPriority::Normal, node::ErrorPriority::Low};

    for ( auto p : prios ) {
        for ( const auto& e : errors ) {
            if ( e.priority != p )
                continue;

            if ( ! reported.contains(e) ) {
                logger().error(e.message, e.context, e.location);
                reported.insert(e);
            }
        }

        if ( reported.size() )
            break;
    }
}

Result<Nothing> ASTContext::collectErrors() {
    std::vector<node::Error> errors;
    recursiveValidateAST(_root, Location(), node::ErrorPriority::NoError, 0, &errors);

    if ( errors.size() ) {
        reportErrors(errors);
        return result::Error("validation failed");
    }

    return Nothing();
}
