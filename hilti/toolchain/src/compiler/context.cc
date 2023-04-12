// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/operator-registry.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using namespace hilti::context;

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
inline const DebugStream AstCache("ast-cache");
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
    for ( auto& u : _unit_cache_by_id )
        u.second->unit = nullptr;

    for ( auto& u : _unit_cache_by_path )
        u.second->unit = nullptr;
}

void Context::cacheUnit(const std::shared_ptr<Unit>& unit) {
    auto entry = std::make_shared<CacheEntry>(unit);
    auto idx = unit->cacheIndex();

    auto i = _unit_cache_by_id.find(idx.scopedID());
    if ( i == _unit_cache_by_id.end() ) {
        HILTI_DEBUG(logging::debug::Compiler,
                    util::fmt("registering %s AST for module %s (%s)", unit->extension(), idx.id, idx.path));

        _unit_cache_by_id.insert({idx.scopedID(), entry});

        if ( ! idx.path.empty() )
            _unit_cache_by_path.insert({idx.path, entry});
    }
    else {
        HILTI_DEBUG(logging::debug::Compiler, util::fmt("updating cached AST for module %s", unit->uniqueID()));
        i->second->unit = unit;
    }
}

std::optional<context::CacheEntry> Context::lookupUnit(const context::CacheIndex& idx,
                                                       const std::optional<hilti::rt::filesystem::path>& extension) {
    if ( auto x = _unit_cache_by_id.find(idx.scopedID()); x != _unit_cache_by_id.end() ) {
        if ( x->second->unit->extension() == extension )
            return *x->second;
    }

    if ( ! idx.path.empty() )
        return lookupUnit(idx.path, idx.scope, extension);
    else
        return {};
}

std::optional<CacheEntry> Context::lookupUnit(const ID& id, const std::optional<ID>& scope,
                                              const hilti::rt::filesystem::path& extension) {
    ID idx = scope ? (*scope + id) : id;
    if ( auto x = _unit_cache_by_id.find(idx); x != _unit_cache_by_id.end() ) {
        if ( x->second->unit->extension() == extension )
            return *x->second;
    }

    return {};
}

std::optional<CacheEntry> Context::lookupUnit(const hilti::rt::filesystem::path& path, const std::optional<ID>& scope,
                                              std::optional<hilti::rt::filesystem::path> ast_extension) {
    if ( ! ast_extension )
        ast_extension = path.extension();

    if ( auto x = _unit_cache_by_path.find(util::normalizePath(path)); x != _unit_cache_by_path.end() ) {
        if ( x->second->unit->extension() == *ast_extension )
            return *x->second;
    }

    return {};
}


static void _dependencies(const std::weak_ptr<Unit>& u, std::vector<std::weak_ptr<Unit>>* seen) {
    auto unit = u.lock();

    for ( const auto& d : *seen ) {
        if ( d.lock().get() == unit.get() )
            return;
    }

    seen->push_back(u);

    for ( const auto& x : unit->dependencies() )
        _dependencies(x, seen);
}

std::vector<std::weak_ptr<Unit>> Context::lookupDependenciesForUnit(const context::CacheIndex& idx,
                                                                    const hilti::rt::filesystem::path& extension) {
    auto m = lookupUnit(idx, extension);
    if ( ! m )
        return {};

    std::vector<std::weak_ptr<Unit>> seen;
    _dependencies(m->unit, &seen);
    seen.erase(seen.begin()); // don't report entry point
    return seen;
}

void Context::dumpUnitCache(const hilti::logging::DebugStream& stream) {
    if ( ! logger().isEnabled(stream) )
        return;

    HILTI_DEBUG(stream, "### Unit cache");
    HILTI_DEBUG(stream, "");

    for ( const auto& x : _unit_cache_by_id ) {
        auto idx = x.first;
        auto unit = x.second->unit;
        HILTI_DEBUG(stream, util::fmt("- %s -> %s %s [%p] [%p]", idx, unit->uniqueID(), unit->extension(),
                                      unit->module().renderedRid(), unit.get()));
    }

    HILTI_DEBUG(stream, "");

    for ( const auto& x : _unit_cache_by_path ) {
        auto idx = x.first;
        auto unit = x.second->unit;
        HILTI_DEBUG(stream, util::fmt("- %s -> %s %s [%p] [%p]", idx, unit->uniqueID(), unit->extension(),
                                      unit->module().renderedRid(), unit.get()));
    }

    HILTI_DEBUG(stream, "");

    for ( const auto& x : _unit_cache_by_id ) {
        auto unit = x.second->unit;
        HILTI_DEBUG(stream, util::fmt("### %s %s [%p] [%p]", unit->uniqueID(), unit->extension(),
                                      unit->module().renderedRid(), unit.get()));

        for ( const auto& d_ : unit->dependencies() ) {
            auto d = d_.lock();
            HILTI_DEBUG(stream, util::fmt("###  Dependency: %s %s [%p] [%p]", d->uniqueID(), d->extension(),
                                          d->module().renderedRid(), d.get()));
        }

        hilti::render(stream, unit->module(), true);
        HILTI_DEBUG(stream, "");
    }

    HILTI_DEBUG(stream, "");
}
