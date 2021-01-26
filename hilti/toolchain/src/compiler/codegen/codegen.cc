// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/string.h>
#include <hilti/ast/declarations/all.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/elements.h>
#include <hilti/compiler/detail/cxx/linker.h>
#include <hilti/compiler/plugin.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;
using namespace hilti::detail::codegen;

namespace {

struct GlobalsVisitor : hilti::visitor::PreOrder<void, GlobalsVisitor> {
    explicit GlobalsVisitor(CodeGen* cg, bool include_implementation)
        : cg(cg), include_implementation(include_implementation) {}

    GlobalsVisitor(const GlobalsVisitor&) = delete;
    GlobalsVisitor(GlobalsVisitor&&) noexcept = delete;

    CodeGen* cg;
    bool include_implementation;

    std::vector<cxx::declaration::Global> globals;
    std::vector<cxx::declaration::Global> constants;

    static void addDeclarations(CodeGen* cg, const Node& module, const ID& module_id, cxx::Unit* unit,
                                bool include_implementation) {
        auto v = GlobalsVisitor(cg, include_implementation);
        for ( auto i : v.walk(module) )
            v.dispatch(i);

        if ( v.globals.empty() && v.constants.empty() )
            return;

        auto ns = cxx::ID(cg->options().cxx_namespace_intern, module_id);

        for ( const auto& c : v.constants )
            unit->add(c);

        if ( ! v.globals.empty() ) {
            if ( include_implementation )
                unit->setUsesGlobals();

            auto t = cxx::declaration::Type{.id = {ns, "__globals_t"}, .type = cxx::Type(v.cxxGlobalsType())};

            auto idx =
                cxx::declaration::Global{.id = {ns, "__globals_index"}, .type = "unsigned int", .linkage = "inline"};

            unit->add(idx);
            unit->add(t);

            auto body = cxx::Block();
            body.addStatement("return hilti::rt::detail::moduleGlobals<__globals_t>(__globals_index)");

            auto body_decl = cxx::declaration::Function{
                .result = "auto",
                .id = {ns, "__globals"},
                .args = {},
                .linkage = "static",
                .inline_body = body,
            };

            unit->add(body_decl);
        }

        if ( include_implementation ) {
            // Create the initGlobals() function.
            auto id = cxx::ID{ns, "__init_globals"};

            auto body_decl =
                cxx::declaration::Function{.result = cg->compile(type::Void(), codegen::TypeUsage::FunctionResult),
                                           .id = id,
                                           .args = {{.id = "ctx", .type = "hilti::rt::Context*"}},
                                           .linkage = "extern"};

            auto body = cxx::Block();
            cg->pushCxxBlock(&body);

            if ( ! v.globals.empty() )
                body.addStatement("hilti::rt::detail::initModuleGlobals<__globals_t>(__globals_index)");

            for ( auto g : v.globals ) {
                if ( g.init )
                    body.addStatement(fmt("__globals()->%s = %s", g.id.local(), *g.init));
                else if ( g.args.size() )
                    body.addStatement(fmt("__globals()->%s = {%s}", g.id.local(), util::join(g.args, ", ")));
            }

            cg->popCxxBlock();

            auto body_impl = cxx::Function{.declaration = body_decl, .body = std::move(body)};
            unit->add(body_decl);
            unit->add(body_impl);
        }
    }

    cxx::type::Struct cxxGlobalsType() const {
        std::vector<cxx::type::struct_::Member> fields;

        for ( const auto& g : globals ) {
            auto f = cxx::declaration::Local{.id = g.id.local(), .type = g.type};
            fields.emplace_back(f);
        }

        return cxx::type::Struct{.members = std::move(fields), .type_name = "__globals_t"};
    }

    void operator()(const declaration::GlobalVariable& n) {
        auto args = util::transform(n.typeArguments(), [this](auto a) { return cg->compile(a); });
        auto init = n.init() ? cg->compile(*n.init()) : cg->typeDefaultValue(n.type());
        auto x = cxx::declaration::Global{.id = {cg->unit()->cxxNamespace(), n.id()},
                                          .type = cg->compile(n.type(), codegen::TypeUsage::Storage),
                                          .args = std::move(args),
                                          .init = std::move(init),
                                          .linkage = "extern"};

        globals.push_back(x);
    }

    void operator()(const declaration::Constant& n) {
        auto x = cxx::declaration::Global{.id = {cg->unit()->cxxNamespace(), n.id()},
                                          .type = cg->compile(n.type(), codegen::TypeUsage::Storage),
                                          .init = cg->compile(n.value()),
                                          .linkage = "const"};

        constants.push_back(x);
    }

    void operator()(const declaration::Type& n) {
        if ( include_implementation )
            cg->addTypeInfoDefinition(n.type());
    }
};

struct Visitor : hilti::visitor::PreOrder<void, Visitor> {
    Visitor(CodeGen* cg, const Scope& module_scope, cxx::Unit* unit) : cg(cg), unit(unit), module_scope(module_scope) {}
    CodeGen* cg;
    cxx::Unit* unit;

    std::optional<ID> module;
    const Scope& module_scope;

    // Top-level nodes.

    void operator()(const Module& n) {
        unit->setModule(n);

        for ( const auto& p : plugin::registry().plugins() ) {
            for ( const auto& i : p.cxx_includes ) {
                auto include = cxx::declaration::IncludeFile{i};
                unit->add(include);
            }
        }

        for ( const auto& i : n.moduleProperties("%cxx-include") ) {
            if ( auto expr = i.expression() ) {
                if ( auto ctor = expr->tryAs<expression::Ctor>() ) {
                    if ( auto str = ctor->ctor().tryAs<ctor::String>() ) {
                        auto include = cxx::declaration::IncludeFile{str->value()};
                        unit->add(include);
                        continue;
                    }
                }
            }

            logger().error("%cxx-include must be used with a constant string");
        }

        auto src = n.id();

        if ( n.meta().location() )
            src += fmt(" (from %s)", n.meta().location().file());

        module = n.id();
        unit->addInitialization(cg->compile(n.statements()));
    }

    void operator()(const declaration::ImportedModule& n) {
        GlobalsVisitor::addDeclarations(cg, *n.module(), n.id(), unit, false);
    }

    void operator()(const declaration::LocalVariable& n) {
        // Ignore, we'll treat them during statement processing.
    }

    void operator()(const declaration::GlobalVariable& n) {
        // Ignore, the GlobalsVisitor() handles them.
    }

    void operator()(const declaration::Constant& n) {
        // Ignore, the GlobalsVisitor() handles them.
    }

    void operator()(const declaration::Parameter& n) {
        // Ignore, we'll treat it during function processing.
    }

    void operator()(const declaration::Function& n, position_t p) {
        // TODO(robin): This method needs a refactoring.

        if ( AttributeSet::find(n.function().attributes(), "&cxxname") &&
             AttributeSet::find(n.function().attributes(), "&have_prototype") )
            return;

        auto f = n.function();
        auto ft = f.type();
        auto ns = unit->cxxNamespace();
        auto id = n.id();
        auto linkage = n.linkage();
        auto is_hook = (n.function().type().flavor() == type::function::Flavor::Hook);

        auto id_module = n.id().sub(-3);

        if ( id_module.empty() )
            id_module = *module;

        auto id_class = n.id().sub(-2);
        auto id_local = n.id().sub(-1);
        auto id_struct_type = (id_module != *module ? ID(id_module, id_class) : id_class);

        cxx::ID cid;
        if ( ! is_hook )
            cid = cxx::ID(*module);

        auto d = cg->compile(id, ft, linkage, f.callingConvention(), f.attributes(), cid);

        if ( auto a = AttributeSet::find(n.function().attributes(), "&cxxname") ) {
            // Just add the prototype. Make sure to skip any custom namespacing.
            d.id = cxx::ID(fmt("::%s", *a->valueAs<std::string>()));
            cg->unit()->add(d);
            return;
        }

        int64_t priority = 0;
        if ( is_hook && f.attributes() ) {
            if ( auto x = f.attributes()->find("&priority") ) {
                if ( auto i = x->valueAs<int64_t>() )
                    priority = *i;
                else
                    // Should have been caught earlier already.
                    logger().error("cannot parse &priority");
            }
        }

        if ( is_hook && n.linkage() == declaration::Linkage::Struct ) {
            // A struct hook.

            if ( ! f.body() )
                // The struct type takes care of the declaration.
                return;

            auto id_hook_impl =
                cxx::ID(unit->cxxNamespace(), cg->uniqueID(fmt("__hook_%s_%s", id_class, id_local), n.function()));
            auto id_hook_stub =
                cxx::ID(cg->options().cxx_namespace_intern, id_module, fmt("__hook_%s_%s", id_class, id_local));

            // Adapt the function we generate.
            d.linkage = "extern";
            d.id = id_hook_impl;

            auto self = scope::lookupID<declaration::Type>(id_struct_type, p);
            assert(self);

            // TODO(robin): This should compile the struct type, not hardcode
            // the runtime representation. However, we don't have access to
            // the type currently.
            d.args.push_back(cxx::declaration::Argument{
                .id = "__self",
                .type = fmt("hilti::rt::ValueReference<%s>&", id_struct_type),
            });

            // Make any additional types the hook needs known to local unit and linker.
            std::list<cxx::declaration::Type> aux_types{
                cxx::declaration::Type{.id = cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                       .type = fmt("struct %s", id_class),
                                       .forward_decl = true}};

            for ( const auto& p : ft.parameters() ) {
                if ( auto t = cg->typeDeclaration(p.type()) )
                    aux_types.push_back(std::move(*t));
            }

            for ( const auto& t : aux_types )
                cg->unit()->add(t); // XXX

            // Tell linker about our implementation.
            auto hook_join =
                cxx::linker::Join{.id = id_hook_stub, .callee = d, .aux_types = aux_types, .priority = priority};

            cg->unit()->add(d);
            cg->unit()->add(hook_join);
        }

        if ( is_hook && n.linkage() != declaration::Linkage::Struct ) {
            // A function hook.
            auto id_module = n.id().sub(-2);

            if ( id_module.empty() )
                id_module = *module;

            auto id_local = id.sub(-1);
            auto id_hook_impl =
                cxx::ID(unit->cxxNamespace(), cg->uniqueID(fmt("__hook_%s_%s", id_class, id_local), n.function()));
            auto id_hook_stub = cxx::ID(cg->options().cxx_namespace_intern, id_module, id_local);

            // Adapt the function we generate.
            d.linkage = "extern";
            d.id = id_hook_impl;

            // Make any additional types the hook needs known to local unit and linker.
            std::list<cxx::declaration::Type> aux_types;

            for ( const auto& p : ft.parameters() ) {
                if ( auto t = cg->typeDeclaration(p.type()) )
                    aux_types.push_back(std::move(*t));
            }

            for ( const auto& t : aux_types )
                cg->unit()->add(t);

            // Tell linker about our implementation.
            auto hook_join = cxx::linker::Join{.id = id_hook_stub,
                                               .callee = d,
                                               .aux_types = aux_types,
                                               .priority = priority,
                                               .declare_only = (! f.body().has_value())};

            cg->unit()->add(hook_join);
        }

        // Common code for all functions, compiling the body.

        if ( ! f.body() )
            return;

        auto body = cg->compile(*f.body());

        // Add runtime stack size check at beginning of function.
        body.addStatementAtFront("hilti::rt::detail::checkStack()");

        if ( n.linkage() == declaration::Linkage::Struct && ! f.isStatic() ) {
            if ( ! is_hook ) {
                // Need a LHS value for __self.
                auto self = cxx::declaration::Local{.id = "__self",
                                                    .type = "auto",
                                                    .init = fmt("%s::__self()", id_struct_type)};
                body.addStatementAtFront(std::move(self));
            }

            cg->pushSelf("__self.derefAsValue()");
        }

        auto cxx_func = cxx::Function{.declaration = d, .body = std::move(body)};

        if ( cg->options().debug_flow ) {
            std::vector<cxx::Expression> args;
            std::vector<std::string> fmts;

            for ( const auto& p : f.type().parameters() ) {
                args.emplace_back(fmt(", %s", cxx::ID(p.id())));
                fmts.emplace_back("%s");
            }

            auto dbg = fmt("HILTI_RT_DEBUG(\"hilti-flow\", hilti::rt::fmt(\"%s: %s(%s)\"%s))", f.meta().location(),
                           d.id, util::join(fmts, ", "), util::join(args, ""));

            cxx_func.body.addStatementAtFront(std::move(dbg));
        }

        cg->unit()->add(cxx_func);

        if ( f.callingConvention() == function::CallingConvention::Extern ) {
            // Create a separate function that we expose to C++. Inside that
            // wrapper we execute the actual function inside a lambda function
            // prepared to suspend. We move also of the functions arguments to
            // the heap, too, because the caller's stack may not be accessible
            // inside the callee due to our fiber runtime swapping stacks out.
            auto body = cxx::Block();
            auto cb = cxx::Block();

            auto outer_args =
                util::join(util::transform(cxx_func.declaration.args,
                                           [](auto& x) {
                                               return fmt("::hilti::rt::resumable::detail::copyArg(%s)", x.id);
                                           }),

                           ", ");

            body.addLocal({.id = "args", .type = "auto", .init = fmt("std::make_tuple(%s)", outer_args)});

            // Move the arguments to the heap. Would be nice to use a
            // unique_ptr here and then move that into the lambda. However,
            // turns out our `Lambda` requires a callback that can be copied,
            // which the unique_ptr would prevent.
            body.addLocal(
                {.id = "args_on_heap", .type = "auto", .init = "std::make_shared<decltype(args)>(std::move(args))"});

            int idx = 0;
            auto inner_args =
                util::join(util::transform(cxx_func.declaration.args,
                                           [&idx](auto& x) { return fmt("std::get<%d>(*args_on_heap)", idx++); }),
                           ", ");

            // If the function returns void synthesize a `Nothing` return value here.
            if ( ft.result().type() != type::Void() )
                cb.addReturn(fmt("%s(%s)", d.id, inner_args));
            else {
                cb.addStatement(fmt("%s(%s)", d.id, inner_args));
                cb.addReturn("hilti::rt::Nothing()");
            }

            body.addLambda("cb", "[args_on_heap](hilti::rt::resumable::Handle* r) -> std::any", std::move(cb));
            body.addLocal({.id = "r", .type = "auto", .init = "std::make_unique<hilti::rt::Resumable>(std::move(cb))"});
            body.addStatement("r->run()");
            body.addReturn("std::move(*r)");

            auto extern_d = d;
            extern_d.id = cxx::ID(
                util::replace(extern_d.id, cg->options().cxx_namespace_intern, cg->options().cxx_namespace_extern));
            extern_d.result = "hilti::rt::Resumable";

            auto extern_cxx_func = cxx::Function{.declaration = extern_d, .body = std::move(body)};

            cg->unit()->add(extern_cxx_func);
            cg->unit()->add(extern_d);
        }

        if ( n.linkage() == declaration::Linkage::Struct && ! f.isStatic() )
            cg->popSelf();

        if ( n.linkage() != declaration::Linkage::Struct )
            cg->unit()->add(d);

        if ( n.linkage() == declaration::Linkage::Init ) {
            // Add a call to this to the module's initialization code.
            cxx::Block call_init_func;
            call_init_func.addStatement(fmt("%s()", d.id));
            cg->unit()->addInitialization(call_init_func);
        }
    }

    void operator()(const declaration::Type& n) { cg->compile(n.type(), codegen::TypeUsage::Storage); }
};

} // anonymous namespace

cxx::Unit* CodeGen::unit() const {
    if ( ! _cxx_unit )
        logger().internalError("CodeGen method cannot be used outside of module compilation");

    return _cxx_unit.get();
}

hilti::Unit* CodeGen::hiltiUnit() const {
    if ( ! _hilti_unit )
        logger().internalError("CodeGen method cannot be used outside of module compilation");

    return _hilti_unit;
}

cxx::declaration::Function CodeGen::compile(const ID& id, type::Function ft, declaration::Linkage linkage,
                                            function::CallingConvention cc, const std::optional<AttributeSet>& fattrs,
                                            std::optional<cxx::ID> namespace_) {
    auto result_ = [&]() {
        auto rt = compile(ft.result().type(), codegen::TypeUsage::FunctionResult);

        switch ( ft.flavor() ) {
            case hilti::type::function::Flavor::Hook:
            case hilti::type::function::Flavor::Method:
            case hilti::type::function::Flavor::Standard: return rt;
            default: util::cannot_be_reached();
        }
    };

    auto usage_ = [&](auto k) {
        switch ( k ) {
            case declaration::parameter::Kind::Copy: return codegen::TypeUsage::CopyParameter;
            case declaration::parameter::Kind::In: return codegen::TypeUsage::InParameter;
            case declaration::parameter::Kind::InOut: return codegen::TypeUsage::InOutParameter;
            case declaration::parameter::Kind::Unknown: logger().internalError("parameter kind not set");
            default: util::cannot_be_reached();
        }
    };

    auto param_ = [&](auto p) {
        auto t = compile(p.type(), usage_(p.kind()));
        return cxx::declaration::Argument{.id = cxx::ID(p.id()), .type = std::move(t)};
    };

    auto linkage_ = [&]() {
        if ( cc == function::CallingConvention::Extern )
            return "extern";

        switch ( linkage ) {
            case declaration::Linkage::Init:
            case declaration::Linkage::Public: return "extern";
            case declaration::Linkage::Private: return "static";
            case declaration::Linkage::Struct: return "";
            default: util::cannot_be_reached();
        }
    };

    auto cxx_id = id;

    if ( linkage == declaration::Linkage::Struct ) {
        // For method implementations, check if the ID is fully scoped with
        // the module name; if so, remove.
        if ( id.sub(0) == _hilti_unit->id() )
            cxx_id = id.sub(1, -1);
    }

    auto ns = ID(options().cxx_namespace_intern);

    if ( namespace_ && *namespace_ )
        ns += *namespace_;
    else
        ns += _hilti_unit->id();

    return cxx::declaration::Function{.result = result_(),
                                      .id = {ns, cxx_id},
                                      .args = util::transform(ft.parameters(), param_),
                                      .linkage = linkage_()};
}

std::vector<cxx::Expression> CodeGen::compileCallArguments(const std::vector<Expression>& args,
                                                           const std::vector<declaration::Parameter>& params) {
    auto kinds = util::transform(params, [](auto& x) { return x.kind(); });
    return util::transform(util::zip2(args, kinds), [this](auto& x) {
        return compile(x.first, x.second == declaration::parameter::Kind::InOut);
    });
}

Result<cxx::Unit> CodeGen::compileModule(Node& root, hilti::Unit* hilti_unit, bool include_implementation) {
    util::timing::Collector _("hilti/compiler/codegen");

    _cxx_unit = std::make_unique<cxx::Unit>(context());
    _hilti_unit = hilti_unit;
    auto v = Visitor(this, *root.scope(), _cxx_unit.get());

    for ( auto i : v.walk(&root) )
        v.dispatch(i);

    GlobalsVisitor::addDeclarations(this, root, ID(std::string(_cxx_unit->moduleID())), _cxx_unit.get(),
                                    include_implementation);

    auto x = _need_decls;
    for ( const auto& t : x ) {
        if ( auto dt = typeDeclaration(t) )
            unit()->add(*dt);
    }

    cxx::Unit u = *_cxx_unit;
    _cxx_unit.reset();
    _hilti_unit = nullptr;

    return std::move(u);
}

Result<cxx::Unit> CodeGen::linkUnits(const std::vector<cxx::linker::MetaData>& mds) {
    util::timing::Collector _("hilti/linker");

    cxx::Linker linker(this);
    for ( const auto& md : mds )
        linker.add(md);

    linker.finalize();
    if ( auto u = linker.linkerUnit() )
        return u;

    return result::Error("linking of meta data failed");
}

cxx::Expression CodeGen::addTmp(const std::string& prefix, const cxx::Expression& init) {
    if ( ! cxxBlock() )
        logger().internalError("codegen: cannot add tmp without an active block");

    int n = 0;
    if ( auto i = _tmp_counters.find(prefix); i != _tmp_counters.end() )
        n = i->second;

    auto tmp = cxx::declaration::Local({.id = cxx::ID(fmt("__%s_%d", prefix, ++n)), .type = "auto", .init = init});
    cxxBlock()->addTmp(tmp);
    _tmp_counters[prefix] = n;
    return std::string(tmp.id);
}

cxx::Expression CodeGen::addTmp(const std::string& prefix, const cxx::Type& t) {
    if ( ! cxxBlock() )
        logger().internalError("codegen: cannot add tmp without an active block");

    int n = 0;
    if ( auto i = _tmp_counters.find(prefix); i != _tmp_counters.end() )
        n = i->second;

    auto tmp = cxx::declaration::Local({.id = cxx::ID(fmt("__%s_%d", prefix, ++n)), .type = t});
    cxxBlock()->addTmp(tmp);
    _tmp_counters[prefix] = n;
    return std::string(tmp.id);
}

cxx::ID CodeGen::uniqueID(const std::string& prefix, const Node& n) {
    std::string x;

    if ( ! n.location() )
        // We rely on the location for creating a unique ID. If we ever arrive
        // here, it shouldn't be too difficult to get location information into
        // the offending node.
        logger().internalError("attempt to create unique codegen ID for node without location");

    return {fmt("%s_%x", prefix, util::hash(n.location()) % 0xffff)};
}
