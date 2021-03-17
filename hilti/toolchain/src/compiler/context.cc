// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/operator-registry.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/plugin.h>

using namespace hilti;
using namespace hilti::context;

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug

Result<Nothing> Options::parseDebugAddl(const std::string& flags) {
    for ( auto i : util::split(flags, ",") ) {
        i = util::trim(i);

        if ( i.empty() )
            continue;
        else if ( i == "trace" )
            debug_trace = true;
        else if ( i == "flow" )
            debug_flow = true;
        else
            return result::Error(
                util::fmt("unknow codegen debug option '%s', must be 'flow' or 'trace' or 'location'", i));
    }

    return Nothing();
}

void Options::print(std::ostream& out) const {
    auto print_one = [&](const char* label, const auto& x) { out << util::fmt("  %25s   %s", label, x) << std::endl; };
    auto print_list = [&](const char* label, const auto& x) {
        if ( x.empty() )
            out << util::fmt("  %25s   <empty>\n", label);
        else {
            bool first = true;
            for ( const auto& i : x ) {
                out << util::fmt("  %25s   %s\n", (first ? label : ""), i);
                first = false;
            }
        }
    };

    out << "\n=== HILTI compiler settings:\n\n";
    print_one("debug", debug);
    print_one("debug_trace", debug_trace);
    print_one("debug_flow", debug_flow);
    print_one("track_location", track_location);
    print_one("skip_validation", skip_validation);
    print_one("optimize", optimize);
    print_list("addl library_paths", library_paths);
    print_one("cxx_namespace_extern", cxx_namespace_extern);
    print_one("cxx_namespace_intern", cxx_namespace_intern);
    print_list("addl cxx_include_paths", cxx_include_paths);

    out << "\n";
}

Context::Context(Options options) : _options(std::move(std::move(options))) {
    operator_::Registry::singleton().printDebug();
}

Context::~Context() {
    // We explicitly clear out the modules to break any reference cycles they
    // may contain.
    for ( auto& m : _modules )
        m.first->as<Module>().clear();
}

const CachedModule& Context::registerModule(const ModuleIndex& idx, Node&& module, bool requires_compilation) {
    auto id = module.as<hilti::Module>().id();
    if ( _module_cache_by_id.find(id) != _module_cache_by_id.end() )
        logger().internalError(util::fmt("module '%s' registered more than once in context", id));

    HILTI_DEBUG(logging::debug::Compiler, util::fmt("registering AST for module %s (%s)", idx.id, idx.path));

    _modules.emplace_back(std::make_unique<Node>(std::move(module)), nullptr);
    auto cached = std::make_shared<CachedModule>(idx, NodeRef(*_modules.back().first));
    cached->requires_compilation = requires_compilation;
    _modules.back().second = cached;
    _module_cache_by_id.insert({idx.id, cached});

    if ( ! idx.path.empty() )
        _module_cache_by_path.insert({idx.path, cached});

    return *cached;
}

void Context::updateModule(const CachedModule& module) {
    assert(module.index.id);

    auto i = _module_cache_by_id.find(module.index.id);
    if ( i == _module_cache_by_id.end() )
        logger().internalError(util::fmt("module '%s' to update has not been registered", module.index.id));

    const auto& cached = i->second;

    if ( cached->node->identity() != module.node->identity() )
        logger().internalError("updating module with name of existing but different AST");

    *cached = module;

    std::string deps = "n/a";
    if ( cached->dependencies ) {
        deps = util::join(util::transform(*cached->dependencies, [](const auto& idx) { return idx.id; }), ", ");
        if ( deps.empty() )
            deps = "(none)";
    }

    std::string requires_compilation = (cached->requires_compilation ? "yes" : "no");
    std::string final = (cached->final ? "yes" : "no");

    HILTI_DEBUG(logging::debug::Compiler,
                util::fmt("updated cached AST for module %s (final: %s, requires_compilation: %s, dependencies: %s)",
                          cached->index.id, final, requires_compilation, deps));
}

std::optional<CachedModule> Context::lookupModule(const ID& id) {
    if ( auto x = _module_cache_by_id.find(id); x != _module_cache_by_id.end() )
        return *x->second;
    else
        return {};
}

std::optional<CachedModule> Context::lookupModule(const hilti::rt::filesystem::path& path) {
    if ( auto x = _module_cache_by_path.find(util::normalizePath(path)); x != _module_cache_by_path.end() )
        return *x->second;
    else
        return {};
}

std::vector<CachedModule> Context::lookupDependenciesForModule(const ID& id) {
    auto m = lookupModule(id);
    if ( ! m )
        return {};

    if ( ! m->dependencies )
        return {};

    std::vector<CachedModule> deps;

    for ( const auto& x : *m->dependencies ) {
        auto d = lookupModule(x.id);
        if ( ! d )
            return {}; // Shouldn't really happen. Assert?

        deps.push_back(*d);
    }

    return deps;
}
