// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/autogen/version.h>
#include <hilti/rt/json.h>
#include <hilti/rt/library.h>
#include <hilti/rt/util.h>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/cxx/linker.h>
#include <hilti/compiler/plugin.h>

using nlohmann::json;

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::cxx::formatter;
using util::fmt;

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug

void cxx::Linker::add(const linker::MetaData& md) {
    auto id = md->at("module").get<std::string>();
    auto path = md->at("path").get<std::string>();
    auto ns = md->at("namespace").get<std::string>();
    _modules.emplace(id, path);

    // Continues logging from CodeGen::linkUnits.
    HILTI_DEBUG(logging::debug::Compiler, fmt("  - module %s (%s)", id, path));

    for ( const auto& j : md->value("joins", json::object_t()) ) {
        for ( auto& s : j.second ) {
            auto& joins = _joins[j.first];
            joins.push_back(s.get<cxx::linker::Join>());
        }
    }

    if ( auto idx = md->value("globals-index", cxx::declaration::Constant()); ! idx.id.empty() )
        _globals.insert(std::move(idx));
}

void cxx::Linker::finalize() {
    cxx::Unit unit(_codegen->context(), "__linker__");
    unit.addComment("Linker code generated for modules:");

    for ( const auto& m : _modules )
        unit.addComment(fmt("  - %s (%s)", m.first, m.second));

    // Create the HLTO version information.
    auto version = rt::library::Version{
        .magic = "v1",
        .hilti_version = configuration().version_number,
        .debug = _codegen->context()->options().debug,
    };

    for ( const auto& p : plugin::registry().plugins() )
        for ( const auto& i : p.cxx_includes )
            unit.add(cxx::declaration::IncludeFile{i});

    auto cxx_namespace = _codegen->context()->options().cxx_namespace_intern;

    unit.add(fmt("const char HILTI_EXPORT HILTI_WEAK * %s_hlto_library_version = R\"(%s)\";", cxx_namespace, version.toJSON()));
    unit.add(fmt("const char HILTI_EXPORT HILTI_WEAK * %s_hlto_bind_to_version = " HILTI_VERSION_FUNCTION_STRING "();", cxx_namespace));

    // Create a scope string that's likely to be unique to this linker module.
    std::size_t hash = 0;
    for ( const auto& [id, path] : _modules ) {
        std::ifstream ifs(path);
        std::string content((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));
        hash = rt::hashCombine(hash, std::hash<std::string>()(content));
    }

    auto scope = hilti::rt::fmt("%" PRIx64, hash);
    unit.add(fmt("const char HILTI_WEAK * %s_hlto_scope = \"%s\";", cxx_namespace, scope));

    std::string init_modules = "nullptr";
    std::string init_globals = "nullptr";

    for ( const auto& j : _joins ) {
        for ( const auto& c : j.second ) {
            if ( ! c.declare_only )
                unit.add(c.callee);

            for ( const auto& t : c.aux_types )
                unit.add(t);
        }
    }

    for ( const auto& j : _joins ) {
        auto impl = cxx::Function();
        auto body = cxx::Block();

        auto sorted_joins = j.second;
        std::sort(sorted_joins.begin(), sorted_joins.end(),
                  [](const auto& x, const auto& y) { return x.priority > y.priority; });

        bool first = true;
        for ( const auto& c : sorted_joins ) {
            if ( first ) {
                impl.declaration = c.callee;
                impl.declaration.id = c.id;
                first = false;
            }

            if ( c.declare_only )
                continue;

            auto args = util::transform(impl.declaration.args, [](auto& a) { return a.id; });

            if ( std::string(c.callee.result) != "void" ) {
                cxx::Block done_body;
                done_body.addStatement("return x;");
                impl.body.addIf(fmt("auto x = %s(%s)", c.callee.id, util::join(args, ", ")), std::move(done_body));
            }
            else
                impl.body.addStatement(fmt("%s(%s)", c.callee.id, util::join(args, ", ")));
        }

        if ( std::string(impl.declaration.result) != "void" )
            impl.body.addStatement("return {}");

        unit.add(impl.declaration);
        unit.add(impl);
    }

    unsigned int cnt = 0;
    for ( auto g : _globals ) {
        g.init = fmt("%u", cnt++);
        g.linkage = "extern";
        unit.add(g);
    }

    unit.finalize();
    _linker_unit = std::move(unit);
}

Result<cxx::Unit> cxx::Linker::linkerUnit() {
    if ( _linker_unit )
        return *_linker_unit;

    return result::Error("linked unit has not been finalized");
}
