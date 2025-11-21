// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <ranges>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/string.h>
#include <hilti/ast/declarations/all.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
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

namespace hilti::logging::debug {
inline const DebugStream Compiler("compiler");
} // namespace hilti::logging::debug

namespace {

// This visitor will only receive AST nodes of the first two levels (i.e.,
// the module and its declarations).
struct GlobalsVisitor : hilti::visitor::PostOrder {
    explicit GlobalsVisitor(CodeGen* cg, cxx::Unit* unit) : cg(cg), unit(unit) {}

    GlobalsVisitor(const GlobalsVisitor&) = delete;
    GlobalsVisitor(GlobalsVisitor&&) noexcept = delete;

    CodeGen* cg;
    cxx::Unit* unit;

    bool include_implementation = false;
    ID current_module;

    std::vector<cxx::declaration::Global> globals;

    // Adds C++ type declarations/definitions for a module's globals if not
    // compiling with --cxx-enable-dynamic-globals.
    void createGlobalsDeclarations() {
        if ( cg->options().cxx_enable_dynamic_globals )
            // Access to globals goes through dynamic accessor function; no
            // need for declarations.
            return;

        auto ns = cxx::ID(cg->options().cxx_namespace_intern, unit->cxxModuleID());

        // We emit globals as optionals so that we can control the life time of
        // the values, in particular wrt destruction when the runtime shuts
        // down.
        for ( auto g : globals ) {
            g.type = fmt("::hilti::rt::Optional<%s>", g.type);

            if ( g.id.namespace_() == ns )
                g.init = "{}";
            else {
                g.linkage = "extern";
                g.init = {};
            }

            unit->add(g);
        }
    }

    // Creates function to access dynamically allocated globals if compiling
    // with --cxx-enable-dynamic-globals.
    void createGlobalsAccessorFunction() {
        if ( ! cg->options().cxx_enable_dynamic_globals )
            // Access to globals is direct, no need for function.
            return;

        auto ns = cxx::ID(cg->options().cxx_namespace_intern, unit->cxxModuleID());
        auto t = cxx::declaration::Type({ns, "__globals_t"}, cxxGlobalsType());

        auto idx = cxx::declaration::Global({ns, "__globals_index"}, "unsigned int", {}, {}, "inline");

        unit->add(idx);
        unit->add(t);

        auto body = cxx::Block();
        body.addStatement("return ::hilti::rt::detail::moduleGlobals<__globals_t>(__globals_index)");

        auto body_decl = cxx::declaration::Function(cxx::declaration::Function::Free, "auto", {ns, "__globals"}, {},
                                                    "static", cxx::declaration::Function::Inline(), std::move(body));

        unit->add(body_decl);
    }

    // Creates function initializing globals.
    void createInitGlobals() {
        auto ns = cxx::ID(cg->options().cxx_namespace_intern, unit->cxxModuleID());
        auto id = cxx::ID{ns, "__init_globals"};

        auto body = cxx::Block();
        cg->pushCxxBlock(&body);

        if ( cg->options().cxx_enable_dynamic_globals ) {
            body.addStatement("::hilti::rt::detail::initModuleGlobals<__globals_t>(__globals_index)");

            for ( auto g : globals ) {
                if ( g.id.namespace_() != ns )
                    continue;

                if ( g.init )
                    body.addStatement(fmt("__globals()->%s = {%s}", g.id.local(), *g.init));
                else if ( g.args.size() )
                    body.addStatement(fmt("__globals()->%s = {%s}", g.id.local(), util::join(g.args, ", ")));
            }
        }
        else {
            for ( const auto& g : globals ) {
                if ( g.id.namespace_() != ns )
                    continue;

                if ( g.init )
                    // Initialize to actual value
                    body.addStatement(fmt("::%s::%s = hilti::rt::optional::make(%s)", ns, g.id.local(), *g.init));
                else if ( g.args.size() )
                    body.addStatement(fmt("::%s::%s = hilti::rt::optional::make<%s>(%s)", ns, g.id.local(), g.type,
                                          util::join(g.args, ", ")));
                else
                    body.addStatement(fmt("::%s::%s = hilti::rt::optional::make(%s{})", ns, g.id.local(), g.type));
            }
        }

        cg->popCxxBlock();

        auto body_decl = cxx::declaration::Function(cxx::declaration::Function::Free, "void", std::move(id),
                                                    {{"ctx", "::hilti::rt::Context*"}}, "extern", std::move(body));
        unit->add(body_decl);
    }

    // Creates function deinitializing globals.
    void createDestroyGlobals() {
        if ( cg->options().cxx_enable_dynamic_globals )
            // Will be implicitly destroyed at termination by the runtime.
            return;

        auto ns = cxx::ID(cg->options().cxx_namespace_intern, unit->cxxModuleID());
        auto id = cxx::ID{ns, "__destroy_globals"};

        auto body = cxx::Block();
        cg->pushCxxBlock(&body);

        for ( const auto& g : globals ) {
            if ( g.id.namespace_() != ns )
                continue;

            body.addStatement(fmt("::%s.reset();", g.id));
        }

        auto body_decl = cxx::declaration::Function(cxx::declaration::Function::Free, "void", std::move(id),
                                                    {{"ctx", "::hilti::rt::Context*"}}, "extern", std::move(body));
        unit->add(body_decl);
    }

    // Returns struct type representing the module's globals when compiling
    // with --cxx-enable-dynamic-globals.
    cxx::type::Struct cxxGlobalsType() const {
        auto ns = cxx::ID(cg->options().cxx_namespace_intern, unit->cxxModuleID());

        std::vector<cxx::type::struct_::Member> fields;

        for ( const auto& g : globals ) {
            if ( g.id.namespace_() != ns )
                continue;

            auto f = cxx::declaration::Local(g.id.local(), g.type);
            fields.emplace_back(f);
        }

        return cxx::type::Struct{.members = std::move(fields), .type_name = "__globals_t"};
    }

    // Add all C++ declarations to unit that a given node will need.
    // TODO: Do we need/use include_implementation? What about %skip-implementation?
    void addCxxDeclarationsFor(Declaration* d, ID module_name, bool include_implementation_, node::CycleDetector* cd);

    // Returns the C++ namespace for the currently processed module.
    auto cxxNamespace() { return cxx::ID(cg->options().cxx_namespace_intern, current_module); }

    void operator()(declaration::Module* n) final {
        // Add any standard includes.
        for ( const auto& p : plugin::registry().plugins() ) {
            for ( const auto& i : p.cxx_includes ) {
                auto include = cxx::declaration::IncludeFile(i);
                unit->add(include);
            }
        }

        // Add any custom includes.
        for ( const auto& i : n->moduleProperties("%cxx-include") ) {
            if ( auto* expr = i->expression() ) {
                if ( auto* ctor = expr->tryAs<expression::Ctor>() ) {
                    if ( auto* str = ctor->ctor()->tryAs<ctor::String>() ) {
                        auto include = cxx::declaration::IncludeFile(str->value());
                        unit->add(include);
                        continue;
                    }
                }
            }

            logger().error("%cxx-include must be used with a constant string");
        }

        unit->addInitialization(cg->compile(n->statements()));
    }

    void operator()(declaration::ImportedModule* n) final {
        // Add any custom includes declared by imported modules.
        auto includes = cg->context()->astContext()->module(*n->uid())->moduleProperties("%cxx-include");
        for ( const auto& i : includes ) {
            auto decl = cxx::declaration::IncludeFile(
                i->expression()->as<expression::Ctor>()->ctor()->as<ctor::String>()->value());
            unit->add(decl);
        }
    }

    void operator()(declaration::GlobalVariable* n) final {
        auto args = node::transform(n->typeArguments(), [this](auto a) { return cg->compile(a); });
        auto init = n->init() ? cg->compile(n->init()) : cg->typeDefaultValue(n->type());
        auto x =
            cxx::declaration::Global({cxxNamespace(), n->id()}, cg->compile(n->type(), codegen::TypeUsage::Storage),
                                     std::move(args), std::move(init),
                                     (n->linkage() == declaration::Linkage::Public ? "" : "static"));

        // Record the global for now, final declarations will be added later
        // once the visitor knows all globals.
        globals.push_back(std::move(x));
    }

    void operator()(declaration::Constant* n) final {
        if ( n->type()->type()->isA<type::Enum>() )
            // Ignore, will be declared through the enum type.
            return;

        auto x =
            cxx::declaration::Constant({cxxNamespace(), n->id()}, cg->compile(n->type(), codegen::TypeUsage::Storage),
                                       cg->compile(n->value()));
        unit->add(x);
    }

    void operator()(declaration::Type* n) final {
        assert(n->typeID());

        auto t = cg->compile(n->type(), codegen::TypeUsage::Storage);
        if ( auto dt = cg->typeDeclaration(n->type()) ) {
            if ( n->linkage() == declaration::Linkage::Public )
                dt->public_ = true;

            unit->add(*dt);
        }

        if ( include_implementation )
            cg->addTypeInfoDefinition(n->type());
    }

    void operator()(declaration::Function* n) final {
        // TODO(robin): This method needs a refactoring.

        if ( n->function()->attributes()->find(hilti::attribute::kind::Cxxname) &&
             n->function()->attributes()->find(hilti::attribute::kind::HavePrototype) )
            return;

        const auto& f = n->function();
        const auto& ft = f->ftype();
        auto ns = cxxNamespace();
        auto id = n->id();
        auto linkage = n->linkage();
        auto is_hook = (n->function()->ftype()->flavor() == type::function::Flavor::Hook);
        auto calling_conv = ft->callingConvention();

        auto id_module = n->id().sub(-3);

        if ( id_module.empty() )
            id_module = current_module;

        auto id_class = n->id().sub(-2);
        auto id_local = n->id().sub(-1);
        const auto& id_struct_type = (id_module != current_module ? ID(id_module, id_class) : id_class);

        cxx::ID cid;
        if ( ! is_hook ) {
            cid = cxx::ID(current_module);
            if ( id.namespace_() && id.sub(0) == id_module ) {
                cid = id.sub(0);
                id = id.sub(1, -1);
            }
        }

        auto d = cg->compile(n, ft, linkage, f->attributes(), cid);

        if ( auto* a = n->function()->attributes()->find(hilti::attribute::kind::Cxxname) ) {
            // Just add the prototype. Make sure to skip any custom namespacing.
            const auto& value = a->valueAsString();
            if ( ! value ) {
                logger().error(fmt("cannot parse &cxxname: %s", value.error()));
                return;
            }

            d.id = ID(*a->valueAsString()).makeAbsolute();
            cg->unit()->add(d);

            return;
        }

        int64_t priority = 0;
        if ( is_hook && f->attributes() ) {
            if ( auto* x = f->attributes()->find(hilti::attribute::kind::Priority) ) {
                if ( auto i = x->valueAsInteger() )
                    priority = *i;
                else
                    // Should have been caught earlier already.
                    logger().error("cannot parse &priority");
            }
        }

        if ( is_hook && n->linkage() == declaration::Linkage::Struct ) {
            // A struct hook.

            if ( ! f->body() )
                // The struct type takes care of the declaration.
                return;

            auto id_hook_impl =
                cxx::ID(cxxNamespace(), cg->uniqueID(fmt("__hook_%s_%s", id_class, id_local), n->function()));
            // Adapt the function we generate.
            d.linkage = "extern";
            d.id = std::move(id_hook_impl);
            d.ftype = cxx::declaration::Function::Free;

            // TODO(robin): This should compile the struct type, not hardcode
            // the runtime representation. However, we don't have access to
            // the type currently.
            // NOLINTNEXTLINE(modernize-use-emplace)
            d.args.push_back(
                cxx::declaration::Argument("__self", fmt("::hilti::rt::ValueReference<%s>&", id_struct_type)));

            // Make any additional types the hook needs known to the linker.
            std::list<cxx::declaration::Type> aux_types{
                cxx::declaration::Type(cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                       fmt("struct %s", id_class), {}, true)};

            for ( const auto& p : ft->parameters() ) {
                auto* type = p->type();

                if ( type->type()->iteratorType() )
                    type = type->type()->elementType();

                while ( type->type()->isReferenceType() )
                    type = type->type()->dereferencedType();

                if ( ! type->type()->isA<type::Struct>() )
                    continue;

                auto tid = type->type()->typeID();

                auto id_module = tid.sub(-2);
                auto id_class = tid.sub(-1);

                if ( id_class.empty() )
                    continue;

                if ( id_module.empty() )
                    id_module = cg->hiltiModule()->scopeID();

                aux_types.push_back(
                    cxx::declaration::Type(cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                           fmt("struct %s", id_class), {}, true));
            }

            cg->unit()->add(d);

            if ( include_implementation ) {
                auto id_hook_stub =
                    cxx::ID(cg->options().cxx_namespace_intern, id_module, fmt("__hook_%s_%s", id_class, id_local));
                // Tell linker about our implementation.
                auto hook_join = cxx::linker::Join{.id = std::move(id_hook_stub),
                                                   .callee = d,
                                                   .aux_types = std::move(aux_types),
                                                   .priority = priority};

                cg->unit()->add(hook_join);
            }
        }

        if ( is_hook && n->linkage() != declaration::Linkage::Struct ) {
            // A function hook.
            auto id_module = n->id().sub(-2);

            if ( id_module.empty() )
                id_module = current_module;

            auto id_local = id.sub(-1);
            auto id_hook_stub = cxx::ID(cg->options().cxx_namespace_intern, id_module, id_local);

            // Adapt the function we generate.
            d.linkage = "extern";
            d.id = cxx::ID(cxxNamespace(), cg->uniqueID(fmt("__hook_%s_%s", id_class, id_local), n->function()));
            d.ftype = cxx::declaration::Function::Free;

            // Add a declaration for the stub that the linker will generate.
            auto stub_decl = d;
            stub_decl.id = id_hook_stub;
            cg->unit()->add(stub_decl);

            // Make any additional types the hook needs known to the linker.
            std::list<cxx::declaration::Type> aux_types;

            for ( const auto& p : ft->parameters() ) {
                auto* type = p->type();

                while ( type->type()->isReferenceType() )
                    type = type->type()->dereferencedType();

                if ( ! type->type()->isA<type::Struct>() )
                    continue;

                auto tid = type->type()->typeID();

                auto id_module = tid.sub(-2);
                auto id_class = tid.sub(-1);

                if ( id_class.empty() )
                    continue;

                if ( id_module.empty() )
                    id_module = cg->hiltiModule()->uid().unique;

                aux_types.push_back(
                    cxx::declaration::Type(cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                           fmt("struct %s", id_class), {}, true));
            }

            if ( include_implementation ) {
                // Tell linker about our implementation.
                auto hook_join = cxx::linker::Join{.id = std::move(id_hook_stub),
                                                   .callee = d,
                                                   .aux_types = std::move(aux_types),
                                                   .priority = priority,
                                                   .declare_only = (! f->body())};

                cg->unit()->add(hook_join);
            }
        }

        // Common code for all functions, compiling the body.

        if ( ! f->body() )
            return;

        auto body = cg->compile(f->body());

        if ( n->linkage() != declaration::Linkage::PreInit )
            // Add runtime stack size check at beginning of function.
            // Cannot do this for "preinit" functions as we won't have a
            // runtime yet.
            body.addStatementAtFront("::hilti::rt::detail::checkStack()");

        // We rely on the profiler's destructor to stop it when the function terminates.
        cg->startProfiler(std::string("hilti/func/") + n->fullyQualifiedID().str(), &body, true);

        if ( n->linkage() == declaration::Linkage::Struct && ! f->isStatic() ) {
            if ( ! is_hook && ! f->isStatic() ) {
                // Need a LHS value for __self.
                auto self = cxx::declaration::Local("__self", "auto", {}, fmt("%s::__self()", id_struct_type));
                body.addStatementAtFront(std::move(self));
            }

            cg->pushSelf("__self.derefAsValue()");
        }

        auto cxx_func = d;

        if ( cg->options().debug_flow ) {
            std::vector<cxx::Expression> args;
            std::vector<std::string> fmts;

            for ( const auto& p : f->ftype()->parameters() ) {
                args.emplace_back(fmt(", %s", cxx::ID(p->id())));
                fmts.emplace_back("%s");
            }

            auto dbg = fmt("HILTI_RT_DEBUG(\"hilti-flow\", ::hilti::rt::fmt(\"%s: %s(%s)\"%s))", f->meta().location(),
                           d.id, util::join(fmts, ", "), util::join(args, ""));

            cxx_func.body->addStatementAtFront(std::move(dbg));
        }

        if ( include_implementation )
            cxx_func.body = std::move(body);

        cg->unit()->add(cxx_func);

        if ( calling_conv == type::function::CallingConvention::Extern ) {
            // Create a separate function that we expose to C++. Inside that
            // wrapper we execute the actual function inside a lambda function
            // prepared to suspend. We move also of the functions arguments to
            // the heap, too, because the caller's stack may not be accessible
            // inside the callee due to our fiber runtime swapping stacks out.
            auto body = cxx::Block();
            auto cb = cxx::Block();

            auto outer_args = util::join(cxx_func.args | std::views::transform([](auto& x) {
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
            auto inner_args = util::join(cxx_func.args | std::views::transform([&idx](auto& x) {
                                             return fmt("std::get<%d>(*args_on_heap)", idx++);
                                         }),
                                         ", ");

            // If the function returns void synthesize a `Nothing` return value here.
            if ( ! ft->result()->type()->isA<type::Void>() )
                cb.addReturn(fmt("%s(%s)", d.id, inner_args));
            else {
                cb.addStatement(fmt("%s(%s)", d.id, inner_args));
                cb.addReturn("::hilti::rt::Nothing()");
            }

            body.addLambda(
                "cb", "[args_on_heap = std::move(args_on_heap)](::hilti::rt::resumable::Handle* r) -> ::hilti::rt::any",
                std::move(cb));
            body.addLocal({"r", "auto", {}, "std::make_unique<::hilti::rt::Resumable>(std::move(cb))"});
            body.addStatement("r->run()");
            body.addReturn("std::move(*r)");

            auto extern_d = d;
            extern_d.id = cxx::ID(
                util::replace(extern_d.id, cg->options().cxx_namespace_intern, cg->options().cxx_namespace_extern));
            extern_d.result = "::hilti::rt::Resumable";
            extern_d.ftype = cxx::declaration::Function::Free;

            if ( include_implementation )
                extern_d.body = std::move(body);

            cg->unit()->add(extern_d);
        }

        if ( calling_conv == type::function::CallingConvention::ExternNoSuspend ) {
            // Create a separate function to expose under the externally
            // visible name, which will simply forward to the actual function.
            auto body = cxx::Block();
            cxx::Expression forward_call = fmt("%s(%s)", d.id, util::join(cxx_func.args, ", "));

            if ( ! ft->result()->type()->isA<type::Void>() )
                body.addReturn(forward_call);
            else
                body.addStatement(forward_call);

            auto extern_d = d;
            extern_d.id = cxx::ID(
                util::replace(extern_d.id, cg->options().cxx_namespace_intern, cg->options().cxx_namespace_extern));
            extern_d.ftype = cxx::declaration::Function::Free;

            if ( include_implementation )
                extern_d.body = std::move(body);

            cg->unit()->add(extern_d);
        }

        if ( n->linkage() == declaration::Linkage::Struct && ! f->isStatic() )
            cg->popSelf();

        if ( include_implementation ) {
            if ( n->linkage() == declaration::Linkage::Init ) {
                // Add a call to this to the module's initialization code.
                cxx::Block call_init_func;
                call_init_func.addStatement(fmt("%s()", d.id));
                cg->unit()->addInitialization(std::move(call_init_func));
            }

            if ( n->linkage() == declaration::Linkage::PreInit ) {
                // Add a call to this to the module's pre-initialization code.
                cxx::Block call_preinit_func;
                call_preinit_func.addStatement(fmt("%s()", d.id));
                cg->unit()->addPreInitialization(std::move(call_preinit_func));
            }
        }
    }
};

} // namespace

CodeGen::CodeGen(const std::shared_ptr<Context>& context)
    : _context(context), _builder(new Builder(context->astContext())) {}

cxx::Unit* CodeGen::unit() const {
    if ( ! _cxx_unit )
        logger().internalError("CodeGen method cannot be used outside of module compilation");

    return _cxx_unit.get();
}

hilti::declaration::Module* CodeGen::hiltiModule() const {
    if ( ! _hilti_module )
        logger().internalError("CodeGen method cannot be used outside of module compilation");

    return _hilti_module;
}

codegen::TypeUsage CodeGen::parameterKindToTypeUsage(parameter::Kind k) {
    switch ( k ) {
        case parameter::Kind::Copy: return codegen::TypeUsage::CopyParameter;
        case parameter::Kind::In: return codegen::TypeUsage::InParameter;
        case parameter::Kind::InOut: return codegen::TypeUsage::InOutParameter;
        case parameter::Kind::Unknown: logger().internalError("parameter kind not set");
    }

    util::cannotBeReached();
}

cxx::declaration::Function CodeGen::compile(Declaration* decl, type::Function* ft, declaration::Linkage linkage,
                                            AttributeSet* fattrs, std::optional<cxx::ID> namespace_) {
    auto result_ = [&]() {
        auto rt = compile(ft->result(), codegen::TypeUsage::FunctionResult);

        switch ( ft->flavor() ) {
            case hilti::type::function::Flavor::Hook:
            case hilti::type::function::Flavor::Method:
            case hilti::type::function::Flavor::Function: return rt;
            default: util::cannotBeReached();
        }
    };

    auto linkage_ = [&]() {
        if ( ft->callingConvention() == type::function::CallingConvention::Extern ||
             ft->callingConvention() == type::function::CallingConvention::ExternNoSuspend )
            return "extern";

        switch ( linkage ) {
            case declaration::Linkage::Init:
            case declaration::Linkage::PreInit:
            case declaration::Linkage::Public: return "extern";
            case declaration::Linkage::Private: return "static";
            case declaration::Linkage::Struct: return "";
            default: util::cannotBeReached();
        }
    };

    const auto& id = decl->id();
    auto cxx_id = cxx::ID(id);

    if ( linkage == declaration::Linkage::Struct ) {
        // For method implementations, check if the ID is fully scoped with
        // the module name; if so, remove.
        if ( id.sub(0).str() == _hilti_module->uid().str() )
            cxx_id = id.sub(1, -1);
    }

    auto ns = ID(options().cxx_namespace_intern);

    if ( namespace_ && *namespace_ )
        ns += *namespace_;
    else
        ns += _hilti_module->uid().str();

    std::vector<cxx::declaration::Argument> parameters;

    for ( auto* p : ft->parameters() ) {
        auto t = compile(p->type(), parameterKindToTypeUsage(p->kind()));

        if ( p->type()->type()->isA<type::Any>() && p->attributes()->find(hilti::attribute::kind::CxxAnyAsPtr) )
            parameters.emplace_back(cxx::ID(fmt("const void* %s", p->id())));
        else
            parameters.emplace_back(cxx::ID(p->id()), std::move(t));

        if ( p->type()->type()->isA<type::Any>() )
            parameters.emplace_back(cxx::ID(fmt("__type_%s", p->id())), cxx::Type("const hilti::rt::TypeInfo*"));
    }

    auto cxx_decl = cxx::declaration::Function(cxx::declaration::Function::Free, result_(), {ns, cxx_id},
                                               std::move(parameters), linkage_());

    if ( linkage == declaration::Linkage::Struct )
        cxx_decl.ftype = cxx::declaration::Function::Method;

    return cxx_decl;
}

std::vector<cxx::Expression> CodeGen::compileCallArguments(const node::Range<Expression>& args,
                                                           const node::Set<declaration::Parameter>& params) {
    auto kinds = node::transform(params, [](const auto& x) { return x->kind(); });

    std::vector<cxx::Expression> x;
    x.reserve(args.size());

    unsigned int i = 0;
    for ( const auto& p : params ) {
        Expression* arg = (i < args.size() ? args[i] : p->default_());

        if ( p->type()->type()->isA<type::Any>() && p->attributes()->find(hilti::attribute::kind::CxxAnyAsPtr) )
            x.emplace_back(fmt("&%s", compile(arg, true)));
        else
            x.emplace_back(compile(arg, p->kind() == parameter::Kind::InOut));

        if ( p->type()->type()->isA<type::Any>() )
            x.emplace_back(typeInfo(arg->type()));

        i++;
    }

    return x;
}

std::vector<cxx::Expression> CodeGen::compileCallArguments(const node::Range<Expression>& args,
                                                           const node::Range<declaration::Parameter>& params) {
    assert(args.size() == params.size());

    auto kinds = node::transform(params, [](auto x) { return x->kind(); });

    std::vector<cxx::Expression> x;
    x.reserve(args.size());
    for ( auto i = 0U; i < args.size(); i++ )
        x.emplace_back(compile(args[i], params[i]->kind() == parameter::Kind::InOut));

    return x;
}

void GlobalsVisitor::addCxxDeclarationsFor(Declaration* d, ID module_name, bool include_implementation_,
                                           node::CycleDetector* cd) {
    if ( cd->haveSeen(d) )
        return;

    cd->recordSeen(d);

    for ( auto* dep : cg->context()->astContext()->dependentDeclarations(d) ) {
        if ( dep != d )
            addCxxDeclarationsFor(dep, dep->fullyQualifiedID().sub(0), include_implementation_, cd);
    }

    current_module = std::move(module_name);

    if ( include_implementation_ )
        include_implementation = (d->fullyQualifiedID().sub(0) == unit->module()->id());
    else
        include_implementation = false;

    dispatch(d);
}

void CodeGen::_addCxxDeclarations(cxx::Unit* unit) {
    GlobalsVisitor v(this, unit);

    node::CycleDetector cd;
    v.addCxxDeclarationsFor(unit->module(), unit->module()->id(), true, &cd);

    for ( const auto& i : unit->module()->childrenOfType<Declaration>() )
        v.addCxxDeclarationsFor(i, unit->module()->id(), true, &cd);

    if ( ! v.globals.empty() ) {
        unit->setUsesGlobals();
        v.createGlobalsAccessorFunction();
        v.createGlobalsDeclarations();
        v.createInitGlobals();
        v.createDestroyGlobals();
    }
}

Result<std::shared_ptr<cxx::Unit>> CodeGen::compileModule(declaration::Module* module) {
    if ( auto cxx = module->cxxUnit() )
        return cxx;

    HILTI_DEBUG(logging::debug::Compiler, fmt("generating C++ for module %s", module->uid()));
    logging::DebugPushIndent __(logging::debug::Compiler);
    util::timing::Collector _("hilti/compiler/codegen");

    _cxx_unit = std::make_unique<cxx::Unit>(context(), module);
    _hilti_module = module;

    _addCxxDeclarations(_cxx_unit.get());

    module->setCxxUnit(std::move(_cxx_unit));
    _cxx_unit.reset();
    _hilti_module = nullptr;

    return module->cxxUnit();
}

Result<std::shared_ptr<cxx::Unit>> CodeGen::linkUnits(const std::vector<cxx::linker::MetaData>& mds) {
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
    return {std::string(tmp.id), Side::LHS};
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
    return {std::string(tmp.id), Side::LHS};
}

cxx::Expression CodeGen::startProfiler(const std::string& name, cxx::Block* block, bool insert_at_front) {
    if ( ! options().enable_profiling )
        return {};

    if ( ! block )
        block = cxxBlock();

    assert(block);
    pushCxxBlock(block);
    auto id = addTmp("profiler", cxx::Type("::hilti::rt::Optional<::hilti::rt::Profiler>"));
    auto stmt = cxx::Expression(fmt("%s = ::hilti::rt::profiler::start(\"%s\")", id, name));

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
    block->addStatement(cxx::Expression(fmt("::hilti::rt::profiler::stop(%s)", profiler)));
}

cxx::Expression CodeGen::unsignedIntegerToBitfield(QualifiedType* t, const cxx::Expression& value,
                                                   const cxx::Expression& bitorder) {
    auto* bf = t->type()->as<type::Bitfield>();

    std::vector<cxx::Expression> bits;
    for ( const auto& b : bf->bits(false) ) {
        auto x = fmt("::hilti::rt::integer::bits(%s, %d, %d, %s)", value, b->lower(), b->upper(), bitorder);

        if ( auto* a = b->attributes()->find(hilti::attribute::kind::Convert) ) {
            pushDollarDollar(std::move(x));
            bits.emplace_back(compile(*a->valueAsExpression()));
            popDollarDollar();
        }
        else
            bits.emplace_back(std::move(x));
    }

    // `noop()` just returns the same value passed in. Without it, the compiler
    // doesn't like the expression we are building, not sure why.
    bits.emplace_back(fmt("::hilti::rt::integer::noop(%s)", value));

    return fmt("::hilti::rt::make_bitfield(%s, %s)", typeInfo(t), util::join(bits, ", "));
}

std::pair<std::string, std::string> CodeGen::cxxTypeForVector(QualifiedType* element_type, bool want_iterator) {
    auto etype = compile(element_type, codegen::TypeUsage::Storage);

    std::string type_addl;

    if ( want_iterator )
        type_addl = (element_type->isConstant() ? "::const_iterator" : "::iterator");

    if ( auto default_ = typeDefaultValue(element_type) )
        return std::make_pair(fmt("::hilti::rt::Vector<%s, ::hilti::rt::vector::Allocator<%s>>%s", etype, etype,
                                  type_addl),
                              fmt(", {%s}", *default_));
    else
        return std::make_pair(fmt("::hilti::rt::Vector<%s>%s", etype, type_addl), std::string(""));
}

cxx::ID CodeGen::uniqueID(const std::string& prefix, Node* n) {
    if ( ! n->location() )
        // We rely on the location for creating a unique ID. If we ever arrive
        // here, it shouldn't be too difficult to get location information into
        // the offending node.
        logger().internalError("attempt to create unique codegen ID for node without location");

    return {fmt("%s_%x", prefix, util::hash(n->location()) % 0xffff)};
}
