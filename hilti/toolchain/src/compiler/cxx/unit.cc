// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>
#include <hilti/hilti.h>

using namespace hilti::detail::cxx;
using namespace hilti::detail::cxx::formatter;
using hilti::util::fmt;

Unit::Unit(const std::shared_ptr<Context>& context, ::hilti::declaration::Module* module)
    : _context(context), _module(module) {
    _module_id = cxx::ID(module->uid().unique);
    _module_path = module->meta().location().file();
}

Unit::Unit(const std::shared_ptr<Context>& context, cxx::ID module_id, const std::string& cxx_code)
    : _context(context), _module_id(std::move(module_id)), _no_linker_meta_data(true), _cxx_code(cxx_code) {}

void Unit::add(std::string_view stmt, const Meta& m) { _statements.emplace_back(stmt); }

void Unit::add(const linker::Join& f) {
    assert(f.callee.ftype == cxx::declaration::Function::Free);

    auto d = f.callee;
    d.id = f.id;
    d.linkage = "extern";
    add(d);

    _linker_joins.insert(f);
}

void Unit::addComment(std::string_view comment) { _comments.emplace_back(comment); }

void Unit::_addHeader(Formatter& f) {
    auto c = fmt("of %s", _module_id);
    if ( _module_path != "" )
        c += fmt(" (from %s)", _module_path);

    f << separator() << comment(fmt("Begin %s", c))
      << comment(fmt("Compiled by HILTI version %s", hilti::configuration().version_string)) << separator()
      << declaration::IncludeFile("hilti/rt/compiler-setup.h") << separator();
}

void Unit::_addModuleInitFunction() {
    auto add_init_function = [&](Context* ctx, auto f, const std::string& id_) {
        auto id = cxx::ID{cxxInternalNamespace(), id_};

        cxx::Block body;
        body.appendFromBlock(std::move(f));

        auto body_decl =
            cxx::declaration::Function(cxx::declaration::Function::Free, "void", id, {}, "extern", std::move(body));
        add(body_decl);
        return id;
    };

    if ( _init_globals )
        add_init_function(context().get(), _init_globals, "__init_globals");

    if ( _init_module )
        add_init_function(context().get(), _init_module, "__init_module");

    if ( _preinit_module )
        add_init_function(context().get(), _preinit_module, "__preinit_module");

    if ( cxxModuleID() != cxx::ID("__linker__") ) {
        auto scope = fmt("%s_hlto_scope", context()->options().cxx_namespace_intern);
        auto extern_scope = cxx::declaration::Global(cxx::ID(scope), "uint64_t", {}, {}, "extern");
        add(extern_scope);

        cxx::Block register_;
        register_.addStatement(fmt("::hilti::rt::Library::setScope(&%s)", scope));
        register_.addStatement(
            fmt("::hilti::rt::detail::registerModule({ \"%s\", %s, %s, %s, %s, %s})", cxxModuleID(), scope,
                _init_module ? "&__init_module" : "nullptr", _uses_globals ? "&__init_globals" : "nullptr",
                _uses_globals && ! context()->options().cxx_enable_dynamic_globals ? "&__destroy_globals" : "nullptr",
                _uses_globals && context()->options().cxx_enable_dynamic_globals ? "&__globals_index" : "nullptr"));

        if ( _preinit_module )
            register_.addStatement(fmt("__preinit_module()"));

        auto id = add_init_function(context().get(), std::move(register_), "__register_module");
        add(fmt("HILTI_PRE_INIT(%s)", id));
    }
}

void Unit::_emitDeclarations(const cxxDeclaration& decl, Formatter& f, Phase phase, bool prototypes_only,
                             bool include_all_implementations) {
    struct Visitor {
        Visitor(Context* ctx, Unit* unit, Formatter& f, Phase phase, bool prototypes_only,
                bool include_all_implementations)
            : ctx(ctx),
              unit(unit),
              f(f),
              phase(phase),
              prototypes_only(prototypes_only),
              include_all_implementations(include_all_implementations) {}

        Context* ctx;
        Unit* unit;
        Formatter& f;
        Phase phase;
        bool prototypes_only;
        bool include_all_implementations;

        bool isTypeInfo(const cxx::ID& id) {
            return id.namespace_() == cxx::ID(ctx->options().cxx_namespace_intern, "type_info::");
        }

        void operator()(const declaration::IncludeFile& d) {
            if ( phase == Phase::Includes )
                f << d;
        }

        void operator()(const declaration::Global& d) {
            if ( phase == Phase::Globals ) {
                f << d;
            }
        }

        void operator()(const declaration::Constant& d) {
            if ( isTypeInfo(d.id) ) {
                // We split these out because creating the type information
                // needs access to all other types.
                if ( phase == Phase::TypeInfoForwards && d.linkage == "extern" ) {
                    f << d;
                    return;
                }
                else if ( phase == Phase::TypeInfos && d.linkage != "extern" ) {
                    f << d;
                    return;
                }
            }

            else if ( phase == Phase::Constants ) {
                f << d;
            }
        }

        void operator()(const declaration::Type& d) {
            if ( phase == Phase::Forwards ) {
                if ( auto base_type = util::split1(d.type).first; base_type == "struct" || base_type == "union" ) {
                    f.enterNamespace(d.id.namespace_());
                    f << base_type << " " << d.id << ";" << eol();
                }
            }

            else if ( phase == Phase::Enums && util::startsWith(d.type, "HILTI_RT_ENUM_WITH_DEFAULT") )
                f << d;

            else if ( phase == Phase::Types && ! util::startsWith(d.type, "HILTI_RT_ENUM_WITH_DEFAULT") )
                f << d;

            else if ( phase == Phase::PublicAliases ) {
                if ( d.public_ && d.id.sub(0).str() == ctx->options().cxx_namespace_intern ) {
                    // Add a type alias mapping the internal type into the public namespace.
                    auto public_id = cxx::ID(ctx->options().cxx_namespace_extern, d.id.sub(1, -1));

                    if ( auto base_type = util::split1(d.type).first; base_type == "struct" || base_type == "union" )
                        // With structs and unions, we may already use the type name as a namespace for related
                        // functions, so need to move the type itself one level lower.
                        public_id = public_id + cxx::ID("Type");

                    f.enterNamespace(public_id.namespace_());
                    f << fmt("using %s = %s;", public_id.local(), d.id) << eol();
                }
            }

            else if ( phase == Phase::Functions ) {
                if ( d.code.size() && ! prototypes_only ) {
                    f << d.code << eol();
                }
            }
        }

        void operator()(const declaration::Function& d) {
            if ( phase == Phase::Functions ) {
                if ( d.ftype == declaration::Function::Type::Method )
                    // Struct type provides the prototype.
                    return;

                auto x = d;
                x.body.reset(); // just output the header
                f << x;
            }
            else if ( phase == Phase::Implementations ) {
                if ( ! d.body )
                    return;

                if ( prototypes_only && d.linkage != "inline" )
                    return;

                if ( include_all_implementations || d.id.sub(0, 2) == unit->cxxInternalNamespace() ||
                     d.id.sub(0, 2) == unit->cxxExternalNamespace() || d.linkage == "inline" )
                    f << separator() << d;
            }
        }
    };

    std::visit(Visitor(context().get(), this, f, phase, prototypes_only, include_all_implementations), decl);
}

void Unit::_generateCode(Formatter& f, bool prototypes_only, bool include_all_implementations) {
    const Phase phases[] = {Phase::TypeInfoForwards, Phase::Forwards,      Phase::Enums,   Phase::Types,
                            Phase::Constants,        Phase::PublicAliases, Phase::Globals, Phase::Functions,
                            Phase::TypeInfos};

    for ( const auto& [_, decl] : _declarations )
        _emitDeclarations(decl, f, Phase::Includes, prototypes_only, include_all_implementations);

    // First output all declarations that are not in a namespace. These should
    // be only low-level, internal stuff that doesn't require further
    // dependencies. Doing these first makes the output a bit cleaner.
    for ( auto phase : phases ) {
        for ( const auto& [id, decl] : _declarations ) {
            if ( ! id.namespace_() )
                _emitDeclarations(decl, f, phase, prototypes_only, include_all_implementations);
        }
    }

    f << separator();

    // Now output the main set of declarations, i.e., everything having a namespace.
    for ( auto phase : phases ) {
        for ( const auto& [id, decl] : _declarations )
            if ( id.namespace_() )
                _emitDeclarations(decl, f, phase, prototypes_only, include_all_implementations);
    }

    f.leaveNamespace();

    if ( ! prototypes_only ) {
        for ( const auto& s : _statements )
            f.printString(s + "\n");

        if ( _statements.size() )
            f << separator();
    }

    for ( const auto& [id_, decl] : _declarations_by_id ) // iterate by ID to sort them alphabetically
        _emitDeclarations(decl, f, Phase::Implementations, prototypes_only, include_all_implementations);
}

hilti::Result<hilti::Nothing> Unit::finalize(bool include_all_implementations) {
    if ( ! _module_id )
        return result::Error("no module set");

    _addModuleInitFunction();

    auto f = Formatter();

    _addHeader(f);

    if ( ! _comments.empty() ) {
        f << comment("");

        for ( const auto& c : _comments )
            f << comment(c);

        f << separator();
    }

    _generateCode(f, false, include_all_implementations);
    _cxx_code = f.str();
    return Nothing();
}

hilti::Result<hilti::Nothing> Unit::print(std::ostream& out) const {
    if ( ! _cxx_code )
        return result::Error("unit does not have any C++ code to print");

    out << *_cxx_code;
    return Nothing();
}

hilti::Result<hilti::Nothing> Unit::createPrototypes(std::ostream& out) {
    if ( ! (_module_id && _cxx_code) )
        return result::Error("cannot generate prototypes for module");

    auto f = Formatter();
    auto guard = fmt("HILTI_PROTOTYPES_%s_H", util::toupper(_module_id));

    f << separator();
    f << comment(fmt("Prototypes for module %s", _module_id));
    f << separator();
    f << fmt("#ifndef %s", guard) << eol();
    f << fmt("#define %s", guard) << eol();
    f << separator();

    _generateCode(f, true, false);

    f << "#endif" << eol();

    out << f.str();
    return Nothing();
}

hilti::detail::cxx::ID Unit::cxxInternalNamespace() const {
    return cxx::ID(context()->options().cxx_namespace_intern, cxxModuleID());
}

hilti::detail::cxx::ID Unit::cxxExternalNamespace() const {
    return cxx::ID(context()->options().cxx_namespace_extern, cxxModuleID());
}

hilti::Result<linker::MetaData> Unit::linkerMetaData() const {
    if ( _no_linker_meta_data )
        return result::Error("module does not have meta data");

    linker::MetaData md;
    md.module = _module_id;
    md.path = util::normalizePath(_module_path);
    md.namespace_ = cxxInternalNamespace();
    md.joins = _linker_joins;

    return md;
}
