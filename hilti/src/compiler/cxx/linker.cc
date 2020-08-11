// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/json.h>
#include <hilti/rt/library.h>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/cxx/linker.h>

using nlohmann::json;

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::cxx::formatter;
using util::fmt;

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug

void cxx::Linker::add(const linker::MetaData& md) {
    auto id = md.at("module").get<std::string>();
    auto path = md.at("path").get<std::string>();
    auto ns = md.at("namespace").get<std::string>();
    _modules.emplace(id, path);

    // Continues logging from CodeGen::linkUnits.
    HILTI_DEBUG(logging::debug::Compiler, fmt("  - module %s (%s)", id, path));

    for ( const auto& j : md.value("joins", json::object_t()) ) {
        for ( auto& s : j.second ) {
            auto& joins = _joins[j.first];
            joins.push_back(s.get<cxx::linker::Join>());
        }
    }

    if ( auto idx = md.value("globals-index", cxx::declaration::Constant()); ! idx.id.empty() )
        _globals.insert(std::move(idx));
}

void cxx::Linker::finalize() {
    cxx::Unit unit(_codegen->context(), "__linker__");
    unit.addComment("Linker code generated for modules:");

    for ( const auto& m : _modules )
        unit.addComment(fmt("  - %s (%s)", m.first, m.second));

    // Create the HLTO version information.
    auto version = rt::library::Version{.magic = "v1",
                                        .hilti_version = configuration().version_number,
                                        .created = rt::time::current_time().seconds(),
                                        .debug = _codegen->context()->options().debug,
                                        .optimize = _codegen->context()->options().optimize};

    unit.add(fmt("const char* __hlto_library_version __attribute__((weak)) = R\"(%s)\";", version.toJSON()));

    if ( ! _modules.empty() )
        unit.add(cxx::declaration::IncludeFile{"hilti/rt/libhilti.h"});

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

        bool first = true;
        for ( const auto& c : j.second ) {
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
