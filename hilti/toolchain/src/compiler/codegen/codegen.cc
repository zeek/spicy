// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/string.h>
#include <hilti/ast/declarations/all.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/ast/scope-lookup.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/struct.h>
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

// This visitor will only receive AST nodes of the first two levels (i.e.,
// the module and its declarations).
struct GlobalsVisitor : hilti::visitor::PreOrder<void, GlobalsVisitor> {
    explicit GlobalsVisitor(CodeGen* cg, bool include_implementation)
        : cg(cg), include_implementation(include_implementation) {}

    GlobalsVisitor(const GlobalsVisitor&) = delete;
    GlobalsVisitor(GlobalsVisitor&&) noexcept = delete;

    CodeGen* cg;
    bool include_implementation;

    std::vector<cxx::declaration::Global> globals;
    std::vector<cxx::declaration::Constant> constants;

    // Helper creating function to access dynamically allocated globals, if needed.
    void createGlobalsAccessorFunction(const Node& module, const ID& module_id, cxx::Unit* unit) {
        if ( ! cg->options().cxx_enable_dynamic_globals )
            // Access to globals is direct, no need for function.
            return;

        auto ns = cxx::ID(cg->options().cxx_namespace_intern, module_id);
        auto t = cxx::declaration::Type{{ns, "__globals_t"}, cxxGlobalsType()};

        auto idx = cxx::declaration::Global{.id = {ns, "__globals_index"}, .type = "unsigned int", .linkage = "inline"};

        unit->add(idx);
        unit->add(t);

        auto body = cxx::Block();
        body.addStatement("return ::hilti::rt::detail::moduleGlobals<__globals_t>(__globals_index)");

        auto body_decl = cxx::declaration::Function{
            .result = "auto",
            .id = {ns, "__globals"},
            .args = {},
            .linkage = "static",
            .inline_body = body,
        };

        unit->add(body_decl);
    }

    // Helper adding declarations for module's globals, if needed.
    void createGlobalsDeclarations(const Node& module, const ID& module_id, cxx::Unit* unit) {
        if ( cg->options().cxx_enable_dynamic_globals )
            // Access to globals goes through dynamic accessor function; no need for declarations.
            return;

        auto ns = cxx::ID(cg->options().cxx_namespace_intern, module_id);

        // We emit globals as optionals so that we can control the life time of
        // the values, in particular wrt destruction when the runtime shuts
        // down.
        for ( const auto& g : globals ) {
            auto cxx_g = g;
            cxx_g.id = cxx::ID{ns, g.id.local()};
            cxx_g.type = fmt("std::optional<%s>", g.type);
            cxx_g.init = {};
            cxx_g.linkage = "extern";
            unit->add(cxx_g);
        }
    }

    // Helper creating function initializing the module's globals.
    void createInitGlobals(const Node& module, const ID& module_id, cxx::Unit* unit) {
        auto ns = cxx::ID(cg->options().cxx_namespace_intern, module_id);
        auto id = cxx::ID{ns, "__init_globals"};

        auto body_decl =
            cxx::declaration::Function{.result = cg->compile(type::void_, codegen::TypeUsage::FunctionResult),
                                       .id = id,
                                       .args = {{.id = "ctx", .type = "::hilti::rt::Context*"}},
                                       .linkage = "extern"};

        auto body = cxx::Block();
        cg->pushCxxBlock(&body);

        if ( cg->options().cxx_enable_dynamic_globals ) {
            body.addStatement("::hilti::rt::detail::initModuleGlobals<__globals_t>(__globals_index)");

            for ( auto g : globals ) {
                if ( g.init )
                    body.addStatement(fmt("__globals()->%s = %s", g.id.local(), *g.init));
                else if ( g.args.size() )
                    body.addStatement(fmt("__globals()->%s = {%s}", g.id.local(), util::join(g.args, ", ")));
            }
        }
        else {
            for ( const auto& g : globals ) {
                auto cxx_g = g;
                cxx_g.type = fmt("std::optional<%s>", g.type);
                cxx_g.init = "{}";
                unit->add(cxx_g);

                if ( g.init )
                    // Initialize to actual value
                    body.addStatement(fmt("::%s::%s = %s", ns, g.id.local(), *g.init));
                else if ( g.args.size() )
                    body.addStatement(fmt("::%s::%s = {%s}", ns, g.id.local(), util::join(g.args, ", ")));
                else
                    body.addStatement(fmt("::%s::%s = %s{}", ns, g.id.local(), g.type));
            }
        }

        cg->popCxxBlock();

        auto body_impl = cxx::Function{.declaration = body_decl, .body = std::move(body)};
        unit->add(body_decl);
        unit->add(body_impl);
    }

    // Helpers creating function destroying the module's globals, if needed.
    void createDestroyGlobals(const Node& module, const ID& module_id, cxx::Unit* unit) {
        if ( cg->options().cxx_enable_dynamic_globals )
            // Will be implicitly destroyed at termination by the runtime.
            return;

        auto ns = cxx::ID(cg->options().cxx_namespace_intern, module_id);
        auto id = cxx::ID{ns, "__destroy_globals"};

        auto body_decl =
            cxx::declaration::Function{.result = cg->compile(type::void_, codegen::TypeUsage::FunctionResult),
                                       .id = id,
                                       .args = {{.id = "ctx", .type = "::hilti::rt::Context*"}},
                                       .linkage = "extern"};

        auto body = cxx::Block();
        cg->pushCxxBlock(&body);

        for ( const auto& g : globals )
            body.addStatement(fmt("::%s::%s.reset();", ns, g.id.local()));

        auto body_impl = cxx::Function{.declaration = body_decl, .body = std::move(body)};
        unit->add(body_decl);
        unit->add(body_impl);
    }

    static void addDeclarations(CodeGen* cg, const Node& module, const ID& module_id, cxx::Unit* unit,
                                bool include_implementation) {
        auto v = GlobalsVisitor(cg, include_implementation);

        v.dispatch(module);

        for ( const auto& i : module.children() )
            v.dispatch(i);

        for ( const auto& c : v.constants )
            unit->add(c);

        if ( ! v.globals.empty() ) {
            v.createGlobalsAccessorFunction(module, module_id, unit);

            if ( include_implementation ) {
                unit->setUsesGlobals();
                v.createInitGlobals(module, module_id, unit);
                v.createDestroyGlobals(module, module_id, unit);
            }
            else
                v.createGlobalsDeclarations(module, module_id, unit);
        }
    }

    cxx::type::Struct cxxGlobalsType() const {
        std::vector<cxx::type::struct_::Member> fields;

        for ( const auto& g : globals ) {
            auto f = cxx::declaration::Local{g.id.local(), g.type};
            fields.emplace_back(f);
        }

        return cxx::type::Struct{.members = std::move(fields), .type_name = "__globals_t"};
    }

    void operator()(const declaration::GlobalVariable& n, position_t p) {
        auto args = node::transform(n.typeArguments(), [this](auto a) { return cg->compile(a); });
        auto init = n.init() ? cg->compile(*n.init()) : cg->typeDefaultValue(n.type());
        auto x = cxx::declaration::Global{.id = {cg->unit()->cxxNamespace(), n.id()},
                                          .type = cg->compile(n.type(), codegen::TypeUsage::Storage),
                                          .args = std::move(args),
                                          .init = std::move(init),
                                          .linkage = (n.linkage() == declaration::Linkage::Public ? "" : "static")};

        globals.push_back(x);
    }

    void operator()(const declaration::Constant& n, position_t p) {
        auto x = cxx::declaration::Constant{.id = {cg->unit()->cxxNamespace(), n.id()},
                                            .type = cg->compile(n.type(), codegen::TypeUsage::Storage),
                                            .init = cg->compile(n.value())};

        constants.push_back(x);
    }

    void operator()(const declaration::Type& n, position_t p) {
        assert(n.typeID());
        cg->compile(n.type(), codegen::TypeUsage::Storage);
        if ( include_implementation ) {
            cg->addTypeInfoDefinition(n.type());

            if ( const auto& dt = cg->typeDeclaration(n.type()) )
                cg->unit()->prioritizeType(dt->id);
        }
    }
};

// This visitor will only receive AST nodes of the first two levels (i.e.,
// the module and its declarations).
struct Visitor : hilti::visitor::PreOrder<void, Visitor> {
    Visitor(CodeGen* cg, const Scope& module_scope, cxx::Unit* unit, hilti::Unit* hilti_unit)
        : cg(cg), unit(unit), hilti_unit(hilti_unit), module_scope(module_scope) {}
    CodeGen* cg;
    cxx::Unit* unit;
    hilti::Unit* hilti_unit;

    std::optional<ID> module;
    const Scope& module_scope;

    // Top-level nodes.

    void operator()(const Module& n) {
        unit->setModule(n, *hilti_unit);

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
        assert(n.unit());
        GlobalsVisitor::addDeclarations(cg, n.unit()->module(), n.id(), unit, false);
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

        const auto& f = n.function();
        const auto& ft = f.ftype();
        auto ns = unit->cxxNamespace();
        const auto& id = n.id();
        auto linkage = n.linkage();
        auto is_hook = (n.function().ftype().flavor() == type::function::Flavor::Hook);

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
            const auto& value = a->valueAsString();
            if ( ! value ) {
                logger().error(fmt("cannot parse &cxxname: %s", value.error()));
                return;
            }

            if ( ! util::startsWith(*value, "::") )
                d.id = cxx::ID(fmt("::%s", *value));
            else
                d.id = cxx::ID(*value);
            cg->unit()->add(d);

            return;
        }

        int64_t priority = 0;
        if ( is_hook && f.attributes() ) {
            if ( auto x = f.attributes()->find("&priority") ) {
                if ( auto i = x->valueAsInteger() )
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

            // TODO(robin): This should compile the struct type, not hardcode
            // the runtime representation. However, we don't have access to
            // the type currently.
            d.args.push_back(cxx::declaration::Argument{
                .id = "__self",
                .type = fmt("::hilti::rt::ValueReference<%s>&", id_struct_type),
            });

            // Make any additional types the hook needs known to local unit and linker.
            std::list<cxx::declaration::Type> aux_types{
                cxx::declaration::Type{cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                       fmt("struct %s", id_class),
                                       {},
                                       true}};

            for ( const auto& p : ft.parameters() ) {
                auto type = p.type();

                if ( type::isIterable(type) )
                    type = type.elementType();

                while ( type::isReferenceType(type) )
                    type = type.dereferencedType();

                if ( ! type.isA<type::Struct>() )
                    continue;

                auto tid = type.typeID();

                auto id_module = tid->sub(-2);
                auto id_class = tid->sub(-1);

                if ( id_class.empty() )
                    continue;

                if ( id_module.empty() )
                    id_module = cg->hiltiUnit()->uniqueID();

                aux_types.push_back(
                    cxx::declaration::Type{cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                           fmt("struct %s", id_class),
                                           {},
                                           true});
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
                auto type = p.type();

                while ( type::isReferenceType(type) )
                    type = type.dereferencedType();

                if ( ! type.isA<type::Struct>() )
                    continue;

                auto tid = type.typeID();

                auto id_module = tid->sub(-2);
                auto id_class = tid->sub(-1);

                if ( id_class.empty() )
                    continue;

                if ( id_module.empty() )
                    id_module = cg->hiltiUnit()->uniqueID();

                aux_types.push_back(
                    cxx::declaration::Type{cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                           fmt("struct %s", id_class),
                                           {},
                                           true});
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

        if ( n.linkage() != declaration::Linkage::PreInit )
            // Add runtime stack size check at beginning of function.
            // Cannot do this for "preinit" functions as we won't have a
            // runtime yet.
            body.addStatementAtFront("::hilti::rt::detail::checkStack()");

        // We rely on the profiler's destructor to stop it when the function terminates.
        cg->startProfiler(std::string("hilti/func/") + n.canonicalID().str(), &body, true);

        if ( n.linkage() == declaration::Linkage::Struct && ! f.isStatic() ) {
            if ( ! is_hook && ! f.isStatic() ) {
                // Need a LHS value for __self.
                auto self = cxx::declaration::Local{"__self", "auto", {}, fmt("%s::__self()", id_struct_type)};
                body.addStatementAtFront(std::move(self));
            }

            cg->pushSelf("__self.derefAsValue()");
        }

        auto cxx_func = cxx::Function{.declaration = d, .body = std::move(body)};

        if ( cg->options().debug_flow ) {
            std::vector<cxx::Expression> args;
            std::vector<std::string> fmts;

            for ( const auto& p : f.ftype().parameters() ) {
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

            body.addLocal({"args", "auto", {}, fmt("std::make_tuple(%s)", outer_args)});

            // Move the arguments to the heap. Would be nice to use a
            // unique_ptr here and then move that into the lambda. However,
            // turns out our `Lambda` requires a callback that can be copied,
            // which the unique_ptr would prevent.
            body.addLocal({"args_on_heap", "auto", {}, "std::make_shared<decltype(args)>(std::move(args))"});

            int idx = 0;
            auto inner_args =
                util::join(util::transform(cxx_func.declaration.args,
                                           [&idx](auto& x) { return fmt("std::get<%d>(*args_on_heap)", idx++); }),
                           ", ");

            // If the function returns void synthesize a `Nothing` return value here.
            if ( ft.result().type() != type::void_ )
                cb.addReturn(fmt("%s(%s)", d.id, inner_args));
            else {
                cb.addStatement(fmt("%s(%s)", d.id, inner_args));
                cb.addReturn("::hilti::rt::Nothing()");
            }

            body.addLambda("cb", "[args_on_heap](hilti::rt::resumable::Handle* r) -> hilti::rt::any", std::move(cb));
            body.addLocal({"r", "auto", {}, "std::make_unique<hilti::rt::Resumable>(std::move(cb))"});
            body.addStatement("r->run()");
            body.addReturn("std::move(*r)");

            auto extern_d = d;
            extern_d.id = cxx::ID(
                util::replace(extern_d.id, cg->options().cxx_namespace_intern, cg->options().cxx_namespace_extern));
            extern_d.result = "::hilti::rt::Resumable";

            auto extern_cxx_func = cxx::Function{.declaration = extern_d, .body = std::move(body)};

            cg->unit()->add(extern_cxx_func);
            cg->unit()->add(extern_d);
        }

        if ( f.callingConvention() == function::CallingConvention::ExternNoSuspend ) {
            // Create a separate function to expose under the externally
            // visible name, which will simply forward to the actual function.
            auto body = cxx::Block();
            cxx::Expression forward_call = fmt("%s(%s)", d.id, util::join(cxx_func.declaration.args, ", "));

            if ( ft.result().type() != type::void_ )
                body.addReturn(forward_call);
            else
                body.addStatement(forward_call);

            auto extern_d = d;
            extern_d.id = cxx::ID(
                util::replace(extern_d.id, cg->options().cxx_namespace_intern, cg->options().cxx_namespace_extern));
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

        if ( n.linkage() == declaration::Linkage::PreInit ) {
            // Add a call to this to the module's pre-initialization code.
            cxx::Block call_preinit_func;
            call_preinit_func.addStatement(fmt("%s()", d.id));
            cg->unit()->addPreInitialization(call_preinit_func);
        }
    }
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

codegen::TypeUsage CodeGen::parameterKindToTypeUsage(declaration::parameter::Kind k) {
    switch ( k ) {
        case declaration::parameter::Kind::Copy: return codegen::TypeUsage::CopyParameter;
        case declaration::parameter::Kind::In: return codegen::TypeUsage::InParameter;
        case declaration::parameter::Kind::InOut: return codegen::TypeUsage::InOutParameter;
        case declaration::parameter::Kind::Unknown: logger().internalError("parameter kind not set");
    }

    util::cannot_be_reached();
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

    auto param_ = [&](auto p) {
        auto t = compile(p.type(), parameterKindToTypeUsage(p.kind()));
        return cxx::declaration::Argument{.id = cxx::ID(p.id()), .type = std::move(t)};
    };

    auto linkage_ = [&]() {
        if ( cc == function::CallingConvention::Extern || cc == function::CallingConvention::ExternNoSuspend )
            return "extern";

        switch ( linkage ) {
            case declaration::Linkage::Init:
            case declaration::Linkage::PreInit:
            case declaration::Linkage::Public: return "extern";
            case declaration::Linkage::Private: return "static";
            case declaration::Linkage::Struct: return "";
            default: util::cannot_be_reached();
        }
    };

    auto cxx_id = cxx::ID(id);

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
                                      .args = node::transform(ft.parameters(), param_),
                                      .linkage = linkage_()};
}

std::vector<cxx::Expression> CodeGen::compileCallArguments(const node::Range<Expression>& args,
                                                           const node::Set<declaration::Parameter>& params) {
    auto kinds = node::transform(params, [](auto& x) { return x.kind(); });

    std::vector<cxx::Expression> x;
    x.reserve(args.size());
    for ( auto i = 0U; i < params.size(); i++ ) {
        Expression arg = (i < args.size() ? args[i] : *params[i].default_());
        x.emplace_back(compile(arg, params[i].kind() == declaration::parameter::Kind::InOut));
    }

    return x;
}

std::vector<cxx::Expression> CodeGen::compileCallArguments(const node::Range<Expression>& args,
                                                           const node::Range<declaration::Parameter>& params) {
    assert(args.size() == params.size());

    auto kinds = node::transform(params, [](auto& x) { return x.kind(); });

    std::vector<cxx::Expression> x;
    x.reserve(args.size());
    for ( auto i = 0U; i < args.size(); i++ )
        x.emplace_back(compile(args[i], params[i].kind() == declaration::parameter::Kind::InOut));

    return x;
}

Result<cxx::Unit> CodeGen::compileModule(Node& root, hilti::Unit* hilti_unit, bool include_implementation) {
    util::timing::Collector _("hilti/compiler/codegen");

    _cxx_unit = std::make_unique<cxx::Unit>(context());
    _hilti_unit = hilti_unit;
    auto v = Visitor(this, *root.scope(), _cxx_unit.get(), hilti_unit);

    v.dispatch(root);

    for ( const auto& i : root.children() )
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

    auto tmp = cxx::declaration::Local(cxx::ID(fmt("__%s_%d", prefix, ++n)), "auto", {}, init);
    cxxBlock()->addTmp(tmp);
    _tmp_counters[prefix] = n;
    return {std::string(tmp.id), cxx::Side::LHS};
}

cxx::Expression CodeGen::addTmp(const std::string& prefix, const cxx::Type& t) {
    if ( ! cxxBlock() )
        logger().internalError("codegen: cannot add tmp without an active block");

    int n = 0;
    if ( auto i = _tmp_counters.find(prefix); i != _tmp_counters.end() )
        n = i->second;

    auto tmp = cxx::declaration::Local(cxx::ID(fmt("__%s_%d", prefix, ++n)), t);
    cxxBlock()->addTmp(tmp);
    _tmp_counters[prefix] = n;
    return {std::string(tmp.id), cxx::Side::LHS};
}

cxx::Expression CodeGen::startProfiler(const std::string& name, cxx::Block* block, bool insert_at_front) {
    if ( ! options().enable_profiling )
        return {};

    if ( ! block )
        block = cxxBlock();

    assert(block);
    pushCxxBlock(block);
    auto id = addTmp("profiler", cxx::Type("std::optional<hilti::rt::Profiler>"));
    auto stmt = cxx::Expression(fmt("%s = hilti::rt::profiler::start(\"%s\")", id, name));

    if ( insert_at_front )
        cxxBlock()->addStatementAtFront(stmt);
    else
        cxxBlock()->addStatement(stmt);

    popCxxBlock();
    return id;
}

void CodeGen::stopProfiler(const cxx::Expression& profiler, cxx::Block* block) {
    if ( ! options().enable_profiling )
        return;

    if ( ! block )
        block = cxxBlock();

    assert(block);
    block->addStatement(cxx::Expression(fmt("hilti::rt::profiler::stop(%s)", profiler)));
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
