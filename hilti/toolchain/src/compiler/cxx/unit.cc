// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <unordered_set>
#include <utility>

#include <hilti/rt/json.h>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>
#include <hilti/hilti.h>

using namespace hilti::detail::cxx;
using namespace hilti::detail::cxx::formatter;
using hilti::util::fmt;
using nlohmann::json;

Unit::Unit(const std::shared_ptr<Context>& context) : _context(context) {}

Unit::Unit(const std::shared_ptr<Context>& context, cxx::ID module_id, const std::string& cxx_code)
    : _context(context), _module_id(std::move(module_id)), _no_linker_meta_data(true), _cxx_code(cxx_code) {}

Unit::Unit(const std::shared_ptr<Context>& context, cxx::ID module_id)
    : _context(context), _module_id(std::move(module_id)), _no_linker_meta_data(true) {}

void Unit::setModule(const hilti::Module& m, const hilti::Unit& hilti_unit) {
    _module_id = hilti_unit.uniqueID();
    _module_path = m.meta().location().file();
}

void Unit::add(const declaration::IncludeFile& i, const Meta& m) { _includes.insert(i); }

void Unit::add(const declaration::Global& g, const Meta& m) {
    if ( auto i = _globals.find(g.id); i != _globals.end() ) {
        if ( i->second == g )
            return;

        logger().internalError(fmt("global '%s' already exists differnently in C++ translation unitn", g.id),
                               m.location());
    }

    _globals.emplace(g.id, g);
    _ids.insert(g.id);

    if ( g.id.namespace_() )
        _namespaces.insert(g.id.namespace_());
}

void Unit::add(const declaration::Constant& c, const Meta& m) {
    if ( c.forward_decl )
        _constants_forward.insert_or_assign(c.id, c);

    else {
        if ( auto i = _constants.find(c.id); i != _constants.end() ) {
            if ( i->second == c )
                return;

            logger().internalError(fmt("constant '%s' already exists differently in C++ translation unit", c.id),
                                   m.location());
        }

        _constants.emplace(c.id, c);
    }

    _ids.insert(c.id);

    if ( c.id.namespace_() )
        _namespaces.insert(c.id.namespace_());
}

void Unit::add(const declaration::Type& t, const Meta& m) {
    if ( t.forward_decl )
        _types_forward.insert_or_assign(t.id, t);

    else {
        if ( auto i = _types.find(t.id); i != _types.end() ) {
            if ( i->second == t )
                return;

            logger().internalError(fmt("type '%s' already exists with different definition in C++ translation unit",
                                       t.id),
                                   m.location());
        }

        _types.insert_or_assign(t.id, t);
    }

    _ids.insert(t.id);

    if ( t.id.namespace_() )
        _namespaces.insert(t.id.namespace_());
}

std::optional<declaration::Type> Unit::lookupType(const ID& id) const {
    if ( auto t = _types.find(id); t != _types.end() )
        return t->second;

    return {};
}

void Unit::add(const declaration::Function& f, const Meta& m) {
    auto current = _function_declarations.equal_range(f.id);

    for ( auto i = current.first; i != current.second; i++ ) {
        if ( i->second == f )
            return;
    }

    _function_declarations.emplace(f.id, f);
    _ids.insert(f.id);

    if ( f.id.namespace_() )
        _namespaces.insert(f.id.namespace_());
}

void Unit::add(const Function& f, const Meta& m) {
    auto current = _function_implementations.equal_range(f.declaration.id);

    for ( auto i = current.first; i != current.second; i++ ) {
        if ( i->second == f )
            return;
    }

    _function_implementations.emplace(f.declaration.id, f);
}

void Unit::add(const std::string& stmt, const Meta& m) { _statements.emplace_back(stmt); }

void Unit::add(const linker::Join& f) {
    auto d = f.callee;
    d.id = f.id;
    d.linkage = "extern";
    add(d);

    _linker_joins.insert(f);
}

void Unit::addComment(const std::string& comment) { _comments.push_back(comment); }

bool Unit::hasDeclarationFor(const cxx::ID& id) { return _ids.find(id) != _ids.end(); }

void Unit::_addHeader(Formatter& f) {
    auto c = fmt("of %s", _module_id);
    if ( _module_path != "" )
        c += fmt(" (from %s)", _module_path);

    f << separator() << comment(fmt("Begin %s", c))
      << comment(fmt("Compiled by HILTI version %s", hilti::configuration().version_string)) << separator()
      << declaration::IncludeFile{.file = "hilti/rt/compiler-setup.h"} << separator();
}

void Unit::_addModuleInitFunction() {
    auto addInitFunction = [&](Context* ctx, auto f, std::string id_) {
        auto id = cxx::ID{cxxNamespace(), std::move(id_)};

        auto body_decl = cxx::declaration::Function{.result = "void", .id = id, .args = {}, .linkage = "extern"};

        cxx::Block body;
        body.appendFromBlock(std::move(f));

        auto body_impl = cxx::Function{.declaration = body_decl, .body = std::move(body)};

        add(body_decl);
        add(body_impl);
        return id;
    };

    if ( _init_globals )
        addInitFunction(context().get(), _init_globals, "__init_globals");

    if ( _init_module )
        addInitFunction(context().get(), _init_module, "__init_module");

    if ( _preinit_module )
        addInitFunction(context().get(), _preinit_module, "__preinit_module");

    if ( moduleID() != cxx::ID("__linker__") ) {
        auto scope = fmt("%s_hlto_scope", context()->options().cxx_namespace_intern);
        auto extern_scope = cxx::declaration::Global{.id = cxx::ID(scope), .type = "const char*", .linkage = "extern"};
        add(extern_scope);

        cxx::Block register_;
        register_.addStatement(
            fmt("::hilti::rt::detail::registerModule({ \"%s\", %s, %s, %s, %s, %s})", moduleID(), scope,
                _init_module ? "&__init_module" : "nullptr", _uses_globals ? "&__init_globals" : "nullptr",
                _uses_globals && ! context()->options().cxx_enable_dynamic_globals ? "&__destroy_globals" : "nullptr",
                _uses_globals && context()->options().cxx_enable_dynamic_globals ? "&__globals_index" : "nullptr"));

        if ( _preinit_module )
            register_.addStatement(fmt("__preinit_module()"));

        auto id = addInitFunction(context().get(), register_, "__register_module");
        add(fmt("HILTI_PRE_INIT(%s)", id));
    }
}

void Unit::_generateCode(Formatter& f, bool prototypes_only) {
    _namespaces.insert("");

    for ( const auto& i : _includes )
        f << i;

    f << separator();

    for ( const auto& ns : _namespaces ) {
        for ( const auto& i : _types_forward ) {
            if ( i.second.id.namespace_() == ns && i.second.forward_decl && i.second.forward_decl_prio )
                f << i.second;
        }
    }

    for ( const auto& ns : _namespaces ) {
        for ( const auto& i : _types_forward ) {
            if ( i.second.id.namespace_() == ns && i.second.forward_decl && ! i.second.forward_decl_prio )
                f << i.second;
        }
    }

    for ( const auto& ns : _namespaces ) {
        if ( prototypes_only && util::endsWith(ns, "::") ) // skip anonymous namespace
            continue;

        for ( const auto& i : _constants_forward ) {
            if ( i.second.id.namespace_() == ns )
                f << i.second;
        }
    }

    for ( const auto& ns : _namespaces ) {
        std::unordered_set<std::string> done;

        // Write out those types first that we have in _types_in_order.
        for ( const auto& id : _types_in_order ) {
            auto i = _types.find(id);
            if ( i == _types.end() )
                continue;

            auto& t = i->second;
            if ( t.id.namespace_() == ns && ! t.forward_decl )
                f << t;

            done.insert(std::string(id));
        }

        // Now write the remaining types.
        for ( const auto& t : _types ) {
            if ( done.find(t.first) != done.end() )
                continue;

            if ( t.second.id.namespace_() == ns && ! t.second.forward_decl )
                f << t.second;
        }

        if ( ! prototypes_only || ! util::endsWith(ns, "::") ) { // skip anonymous namespace
            if ( ID(ns) == cxx::ID(context()->options().cxx_namespace_intern, "type_info::") )
                // We force this to come last later below because creating the type information needs access to all
                // other types.
                continue;

            for ( const auto& i : _constants ) {
                if ( i.second.id.namespace_() == ns )
                    f << i.second;
            }

            for ( const auto& i : _globals ) {
                if ( i.second.id.namespace_() == ns )
                    f << i.second;
            }
        }

        for ( const auto& i : _function_declarations ) {
            if ( i.second.id.namespace_() != ns )
                continue;

            auto needs_separator = (i.second.inline_body && i.second.inline_body->size() > 1);

            if ( needs_separator )
                f << separator();

            f << i.second;

            if ( needs_separator )
                f << separator();
        }
    }

    // Add the contents of the type information namespace. We know that there are only constants in there.
    if ( ! prototypes_only ) {
        for ( const auto& i : _constants ) {
            if ( i.second.id.namespace_() == cxx::ID(context()->options().cxx_namespace_intern, "type_info::") )
                f << i.second;
        }
    }

    f.leaveNamespace();

    // Add any inline code that types may have defined.
    for ( const auto& ns : _namespaces ) {
        for ( const auto& t : _types ) {
            if ( t.second.id.namespace_() == ns && t.second.inline_code.size() ) {
                f.enterNamespace(t.second.id.namespace_());
                f << t.second.inline_code << eol();
            }
        }
    }

    f.leaveNamespace();

    if ( prototypes_only )
        return;

    for ( const auto& s : _statements )
        f.printString(s + "\n");

    if ( _statements.size() )
        f << separator();

    for ( const auto& i : _function_implementations )
        f << separator() << i.second;

    if ( auto meta = linkerMetaData() ) {
        std::stringstream json;
        json << **meta;
        f << separator();
        f << "/* __HILTI_LINKER_V1__" << eol();
        f << json.str() << eol();
        f << "*/" << eol() << separator();
    }
}

hilti::Result<hilti::Nothing> Unit::finalize() {
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

    _generateCode(f, false);
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

    f << separator();
    f << comment(fmt("Prototypes for module %s", _module_id));
    f << separator();
    f << fmt("#ifndef HILTI_PROTOTYPES_%s_H", util::toupper(_module_id)) << eol();
    f << separator();

    _generateCode(f, true);

    f << "#endif" << eol();

    out << f.str();
    return Nothing();
}

void Unit::importDeclarations(const Unit& other) {
    const auto m = Meta(Location("<import>"));

    for ( const auto& i : other._constants_forward )
        add(i.second, m);

    for ( const auto& i : other._constants )
        add(i.second, m);

    for ( const auto& i : other._types )
        add(i.second, m);

    for ( const auto& i : other._types_forward )
        add(i.second, m);

    for ( const auto& i : other._types )
        add(i.second, m);

    for ( const auto& i : other._function_declarations ) {
        if ( std::string(i.second.linkage).find("extern") == std::string::npos &&
             std::string(i.second.linkage).find("inline") == std::string::npos )
            continue;

        add(i.second, m);
    }

    for ( const auto& i : other._function_implementations ) {
        if ( std::string(i.second.declaration.linkage).find("inline") == std::string::npos )
            continue;

        add(i.second, m);
    }

    for ( const auto& i : other._includes )
        add(i, m);
}

hilti::detail::cxx::ID Unit::cxxNamespace() const {
    return cxx::ID(context()->options().cxx_namespace_intern, moduleID());
}

hilti::Result<linker::MetaData> Unit::linkerMetaData() const {
    if ( _no_linker_meta_data )
        return result::Error("module does not have meta data");

    auto joins = json::object();

    for ( const auto& f : _linker_joins )
        joins[f.id].push_back(f);

    json j;
    j["version"] = 1;
    j["module"] = _module_id;
    j["path"] = util::normalizePath(_module_path);
    j["namespace"] = cxxNamespace();

    if ( ! joins.empty() )
        j["joins"] = joins;

    return linker::MetaData(j);
}

std::pair<bool, std::optional<linker::MetaData>> Unit::readLinkerMetaData(std::istream& input) {
    std::string line;

    bool in_md = false;
    std::string data;

    while ( std::getline(input, line) ) {
        if ( in_md ) {
            if ( util::startsWith(util::trim(line), "*/") )
                in_md = false;
        }

        if ( in_md )
            data += line;

        if ( ! in_md ) {
            if ( util::trim(line) == "/* __HILTI_LINKER_V1__" )
                in_md = true;
        }
    }

    if ( input.bad() )
        return std::make_pair(false, std::nullopt);

    if ( data.empty() )
        return std::make_pair(true, std::nullopt);

    try {
        auto md = nlohmann::json::parse(data);
        return std::make_pair(true, md);
    } catch ( nlohmann::json::parse_error& e ) {
        return std::make_pair(false, std::nullopt);
    }
}

void linker::to_json(nlohmann::json& j, const linker::Join& x) {
    j = json{
        {"id", x.id},
        {"callee", x.callee},
        {"aux_types", x.aux_types},
        {"priority", x.priority},
        {"declare_only", x.declare_only},
    };
}

void linker::from_json(const nlohmann::json& j, linker::Join& x) {
    x.id = j.at("id").get<ID>();
    x.callee = j.at("callee").get<declaration::Function>();
    x.aux_types = j.at("aux_types").get<std::list<declaration::Type>>();
    x.priority = j.at("priority").get<int>();
    x.declare_only = j.at("declare_only").get<bool>();
}
