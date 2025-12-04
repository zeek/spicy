// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <ranges>

#include <hilti/rt/autogen/version.h>
#include <hilti/rt/library.h>
#include <hilti/rt/util.h>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/cxx/linker.h>
#include <hilti/compiler/plugin.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::cxx::formatter;
using util::fmt;

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug

void cxx::Linker::add(const linker::MetaData& md) {
    _modules.emplace(md.module, md.path);

    // Continues logging from CodeGen::linkUnits.
    HILTI_DEBUG(logging::debug::Compiler, fmt("  - module %s (%s)", md.module, md.path));

    for ( const auto& j : md.joins ) {
        auto& joins = _joins[j.id];
        joins.push_back(j);
    }

    if ( const auto& idx = md.globals_index; ! idx.id.empty() )
        _globals.insert(idx);
}

void cxx::Linker::finalize() {
    auto unit = std::shared_ptr<cxx::Unit>(new cxx::Unit(_codegen->context(), "__linker__"));
    unit->addComment("Linker code generated for modules:");

    for ( const auto& m : _modules )
        unit->addComment(fmt("  - %s (%s)", m.first, m.second));

    // Create the HLTO version information.
    auto version = rt::library::Version{
        .magic = "v1",
        .hilti_version = configuration().version_number,
        .debug = _codegen->context()->options().debug,
    };

    for ( const auto& p : plugin::registry().plugins() )
        for ( const auto& i : p.cxx_includes )
            unit->add(cxx::declaration::IncludeFile(i));

    // Note we don't qualify the two subsequent globals with
    // `cxx_namespace_intern` because we need these exact names; that's what
    // the runtime lbirary is likewise hard-coded to expect.
    unit->add(fmt("const char HILTI_EXPORT HILTI_WEAK * %s = R\"(%s)\";",
                  HILTI_INTERNAL_GLOBAL_ID("hlto_library_version"), version.toJSON()));
    unit->add(fmt("const char HILTI_EXPORT HILTI_WEAK * %s = " HILTI_VERSION_FUNCTION_STRING "();",
                  HILTI_INTERNAL_GLOBAL_ID("hlto_bind_to_version")));

    // Create a variable for the linker scope, but initialize it to magic value
    // `0` encoding unset. We will inject the actual scope at runtime when the
    // library is loaded.
    const auto& cxx_namespace = _codegen->context()->options().cxx_namespace_intern;
    unit->add(fmt("HILTI_HIDDEN uint64_t %s_hlto_scope = 0;", cxx_namespace));

    for ( const auto& j : _joins ) {
        for ( const auto& c : j.second ) {
            if ( ! c.declare_only )
                unit->add(c.callee);

            for ( const auto& t : c.aux_types )
                unit->add(t);
        }
    }

    for ( const auto& j : _joins ) {
        std::optional<cxx::declaration::Function> impl;

        auto sorted_joins = j.second;
        std::ranges::sort(sorted_joins, [](const auto& x, const auto& y) { return x.priority > y.priority; });

        for ( const auto& c : sorted_joins ) {
            if ( ! impl ) {
                impl = c.callee;
                impl->id = c.id;
                impl->body = cxx::Block();
                impl->ftype = cxx::declaration::Function::Free;
            }

            if ( c.declare_only )
                continue;

            auto args = impl->args | std::views::transform([](auto& a) { return a.id; });

            if ( std::string(c.callee.result) != "void" ) {
                cxx::Block done_body;
                done_body.addStatement("return x;");
                impl->body->addIf(fmt("auto x = %s(%s)", c.callee.id, util::join(args, ", ")), std::move(done_body));
            }
            else
                impl->body->addStatement(fmt("%s(%s)", c.callee.id, util::join(args, ", ")));
        }

        if ( std::string(impl->result) != "void" )
            impl->body->addStatement("return {}");

        unit->add(*impl);
    }

    unsigned int cnt = 0;
    for ( auto g : _globals ) {
        g.init = fmt("%u", cnt++);
        g.linkage = "extern";
        unit->add(g);
    }

    unit->finalize(true);
    _linker_unit = std::move(unit);
}

Result<std::shared_ptr<cxx::Unit>> cxx::Linker::linkerUnit() {
    if ( _linker_unit )
        return _linker_unit;

    return result::Error("linked unit has not been finalized");
}
