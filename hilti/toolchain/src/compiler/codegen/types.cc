// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/types/all.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/ast-dumper.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>
#include <hilti/compiler/printer.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::codegen;

using util::fmt;

namespace {

struct VisitorDeclaration : hilti::visitor::PreOrder {
    VisitorDeclaration(CodeGen* cg, QualifiedType* type, util::Cache<cxx::ID, cxx::declaration::Type>* cache)
        : cg(cg), type(type), cache(cache) {}

    CodeGen* cg;
    QualifiedType* type = nullptr;
    util::Cache<cxx::ID, cxx::declaration::Type>* cache;
    std::list<cxx::declaration::Type> dependencies;

    std::optional<cxx::declaration::Type> result;

    void addDependency(QualifiedType* t) {
        for ( auto&& t : cg->typeDependencies(t) )
            dependencies.push_back(std::move(t));
    }

    void operator()(type::Bitfield* n) final {
        for ( const auto& b : n->bits(true) )
            addDependency(b->itemType());
    }

    void operator()(type::Struct* n) final {
        auto scope = cxx::ID{cg->unit()->cxxInternalNamespace()};
        auto sid = cxx::ID{n->typeID()};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        result = cache->getOrCreate(
            id,
            []() {
                // Just return an empty dummy for now to avoid cyclic recursion.
                return cxx::declaration::Type();
            },
            [&](auto& dummy) {
                std::vector<cxx::declaration::Argument> args;
                std::vector<cxx::type::struct_::Member> fields;

                cxx::Block ctor;

                cxx::Block self_body;
                self_body.addStatement(util::fmt("return ::hilti::rt::ValueReference<%s>::self(this)", id));

                auto self = cxx::declaration::Function(cxx::declaration::Function::Free, "auto", "__self", {}, "",
                                                       cxx::declaration::Function::Inline(), std::move(self_body));

                fields.emplace_back(std::move(self));

                for ( const auto& p : n->parameters() ) {
                    cxx::Type type = cg->compile(p->type(), cg->parameterKindToTypeUsage(p->kind()));
                    cxx::Type internal_type = cg->compile(p->type(), codegen::TypeUsage::Storage);

                    if ( p->type()->type()->isReferenceType() ) {
                        // We turn reference types into weak references for
                        // storage so that copying a struct won't cause
                        // potentially expensive copies or let us hold on to
                        // objects longer than they'd otherwise stick around.
                        assert(p->type()->type()->isReferenceType());
                        internal_type =
                            cg->compile(cg->builder()
                                            ->qualifiedType(cg->builder()->typeWeakReference(p->type()
                                                                                                 ->type()
                                                                                                 ->dereferencedType(),
                                                                                             p->meta()),
                                                            p->type()->constness()),
                                        codegen::TypeUsage::Storage);
                    }

                    std::optional<cxx::Expression> default_;
                    if ( auto* x = p->default_() )
                        default_ = cg->compile(x);
                    else
                        default_ = cg->typeDefaultValue(p->type());

                    auto arg = cxx::declaration::Argument(cxx::ID(fmt("__p_%s", p->id())), std::move(type),
                                                          std::move(default_), std::move(internal_type));
                    args.emplace_back(std::move(arg));
                }

                for ( const auto& f : n->fields() ) {
                    if ( f->isNoEmit() )
                        continue;

                    if ( auto* ft = f->type()->type()->tryAs<type::Function>() ) {
                        auto d = cg->compile(f, ft, declaration::Linkage::Struct, f->attributes());

                        if ( f->isStatic() )
                            d.linkage = "static";

                        if ( auto* func = f->inlineFunction(); func && func->body() ) {
                            auto cxx_body = cxx::Block();

                            if ( ! f->isStatic() ) {
                                // Need a LHS for __self.
                                auto tid = n->typeID();

                                if ( ! tid )
                                    logger().internalError("Struct type with hooks does not have a type ID");

                                auto id_module = tid.sub(-2);
                                auto id_class = tid.sub(-1);

                                if ( id_module.empty() )
                                    id_module = cg->hiltiModule()->uid().unique;

                                auto id_type = cxx::ID(id_module, id_class);
                                auto self = cxx::declaration::Local("__self", "auto", {}, fmt("%s::__self()", id_type));
                                cxx_body.addLocal(self);
                            }

                            cg->compile(func->body(), &cxx_body);

                            auto method_impl = d;
                            method_impl.id = cxx::ID(scope, sid, f->id());
                            method_impl.linkage = "inline";
                            method_impl.body = std::move(cxx_body);
                            cg->unit()->add(method_impl);
                        }

                        if ( ft->flavor() == type::function::Flavor::Hook ) {
                            auto tid = n->typeID();

                            if ( ! tid )
                                logger().internalError("Struct type with hooks does not have a type ID");

                            auto id_module = tid.sub(-2);
                            auto id_class = tid.sub(-1);
                            const auto& id_local = f->id();

                            if ( id_module.empty() )
                                id_module = cg->hiltiModule()->uid().unique;

                            auto id_hook = cxx::ID(cg->options().cxx_namespace_intern, id_module,
                                                   fmt("__hook_%s_%s", id_class, id_local));
                            auto id_type = cxx::ID(id_module, id_class);

                            auto args = util::transform(d.args, [](auto& a) { return a.id; });
                            args.emplace_back("__self");

                            auto method_body = cxx::Block();

                            // Need a LHS for __self.
                            auto self = cxx::declaration::Local("__self", "auto", {}, fmt("%s::__self()", id_type));
                            method_body.addLocal(self);
                            method_body.addStatement(fmt("return %s(%s)", id_hook, util::join(args, ", ")));

                            auto method_impl = d;
                            method_impl.id = cxx::ID(scope, sid, f->id());
                            method_impl.linkage = "inline";
                            method_impl.body = std::move(method_body);
                            cg->unit()->add(method_impl);

                            std::list<cxx::declaration::Type> aux_types = {
                                cxx::declaration::Type(cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                                       fmt("struct %s", id_class), {}, true)};

                            for ( const auto& p : ft->parameters() ) {
                                for ( auto t : cg->typeDependencies(p->type()) )
                                    aux_types.push_back(std::move(t));
                            }

                            d.ftype = cxx::declaration::Function::Free;
                            auto hook = cxx::linker::Join{.id = cxx::ID(std::move(id_hook)),
                                                          .callee = d,
                                                          .aux_types = std::move(aux_types),
                                                          .declare_only = true};

                            auto* vref =
                                cg->builder()->qualifiedType(cg->builder()->typeValueReference(type), Constness::Const);
                            // NOLINTNEXTLINE(modernize-use-emplace)
                            hook.callee.args.push_back(
                                cxx::declaration::Argument("__self",
                                                           cg->compile(vref, codegen::TypeUsage::InOutParameter)));
                            cg->unit()->add(hook);
                        }

                        fields.emplace_back(std::move(d));
                        continue;
                    }

                    auto t = cg->compile(f->type(), codegen::TypeUsage::Storage);

                    if ( f->isOptional() )
                        t = fmt("::hilti::rt::Optional<%s>", t);

                    std::optional<cxx::Expression> default_;

                    // Push a block so all values needed to default-initialize
                    // fields have a block. This is required if compiling the
                    // value needs to e.g., create temporaries.
                    cg->pushCxxBlock(&ctor);

                    if ( ! f->isOptional() ) {
                        cg->pushSelf("__self()");
                        if ( auto* x = f->default_() )
                            default_ = cg->compile(x);
                        else
                            default_ = cg->typeDefaultValue(f->type());
                        cg->popSelf();
                    }

                    cg->popCxxBlock();

                    if ( default_ )
                        ctor.addStatement(fmt("%s = %s", cxx::ID(f->id()), *default_));

                    // Do not pass a default value here since initialization of
                    // the member happens (and needs to happen) via the ctor
                    // block above to guarantee we have a block.
                    auto x = cxx::declaration::Local(cxx::ID(f->id()), std::move(t), {}, {},
                                                     (f->isStatic() ? "inline static" : ""));

                    if ( f->type()->type()->isA<type::Bitfield>() )
                        x.typeinfo_bitfield = cg->typeInfo(f->type());

                    fields.emplace_back(std::move(x));
                }

                if ( n->hasFinalizer() ) {
                    // Call the finalizer hook from a C++ destructor.
                    cxx::Block dtor_body;
                    dtor_body.addStatement("_0x7e_finally()");

                    auto dtor =
                        cxx::declaration::Function(cxx::declaration::Function::Free, "",
                                                   cxx::ID::fromNormalized(
                                                       fmt("~%s", id.local())), // don't escape the ~
                                                   {}, "", cxx::declaration::Function::Inline(), std::move(dtor_body));

                    dtor.ftype = cxx::declaration::Function::Method;
                    fields.emplace_back(std::move(dtor));
                }

                auto t = cxx::type::Struct{.args = std::move(args),
                                           .members = std::move(fields),
                                           .type_name = cxx::ID(id.local()),
                                           .ctor = std::move(ctor),
                                           .add_ctors = true};

                // Only emit full inline code if we are generating the unit declaring this type.
                if ( n->typeID().namespace_() == cg->unit()->module()->id() )
                    return cxx::declaration::Type{id, t, t.code()};
                else
                    return cxx::declaration::Type{id, t, {}};
            });
    }

    void operator()(type::Tuple* n) final {
        for ( const auto& e : n->elements() )
            addDependency(e->type());
    }

    void operator()(type::Union* n) final {
        assert(n->typeID());

        auto scope = cxx::ID{cg->unit()->cxxInternalNamespace()};
        auto sid = cxx::ID{n->typeID()};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        std::vector<cxx::type::union_::Member> fields;
        for ( const auto& f : n->fields() ) {
            auto t = cg->compile(f->type(), codegen::TypeUsage::Storage);
            auto x = cxx::declaration::Local(cxx::ID(f->id()), std::move(t));
            fields.emplace_back(std::move(x));
        }

        auto t = cxx::type::Union{.members = std::move(fields), .type_name = cxx::ID(id.local())};
        result = cxx::declaration::Type(std::move(id), t);
    }

    void operator()(type::Vector* n) final {
        if ( n->elementType()->type()->isA<type::Unknown>() )
            addDependency(n->elementType());
    }

    void operator()(type::Enum* n) final {
        assert(n->typeID());

        auto scope = cxx::ID{cg->unit()->cxxInternalNamespace()};
        auto sid = cxx::ID{n->typeID()};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);
        auto labels = util::transform(n->labels(), [](auto l) { return std::make_pair(cxx::ID(l->id()), l->value()); });
        auto t = cxx::type::Enum{.labels = std::move(labels), .type_name = cxx::ID(id.local())};
        auto decl = cxx::declaration::Type(std::move(id), t, {}, true);
        dependencies.push_back(decl);
        result = decl;
    }

    void operator()(type::Exception* n) final {
        assert(n->typeID());

        auto scope = cxx::ID{cg->unit()->cxxInternalNamespace()};
        auto sid = cxx::ID{n->typeID()};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        std::string base_ns = "::hilti::rt";
        std::string base_cls = "UsageError";

        if ( auto* b = n->baseType() ) {
            auto x = cxx::ID(cg->compile(cg->builder()->qualifiedType(b, Constness::Const), codegen::TypeUsage::Ctor));
            base_ns = x.namespace_();
            base_cls = x.local();
        }

        auto id = cxx::ID(scope, sid);

        // Exception instances all need an implementation of a virtual
        // destructor to trigger generation of their vtable.
        auto func = cxx::declaration::Function(cxx::declaration::Function::Free, "",
                                               cxx::ID::fromNormalized(fmt("%s::~%s", id, id.local())), {}, "inline",
                                               cxx::Block());
        func.ftype = cxx::declaration::Function::Method;
        cg->unit()->add(func);

        result =
            cxx::declaration::Type(id, fmt("HILTI_EXCEPTION_NS(%s, %s, %s)", id.local(), base_ns, base_cls), {}, true);
    }
};

struct VisitorStorage : hilti::visitor::PreOrder {
    VisitorStorage(CodeGen* cg, QualifiedType* type, util::Cache<cxx::ID, CxxTypes>* cache, codegen::TypeUsage usage)
        : cg(cg), type(type), cache(cache), usage(usage) {}

    CodeGen* cg;
    QualifiedType* type = nullptr;
    util::Cache<cxx::ID, CxxTypes>* cache;
    codegen::TypeUsage usage;

    std::optional<CxxTypes> result;

    void operator()(type::Address* n) final { result = CxxTypes{.base_type = "::hilti::rt::Address"}; }

    void operator()(type::Any* n) final { result = CxxTypes{.base_type = "::hilti::rt::any"}; }

    void operator()(type::Bool* n) final { result = CxxTypes{.base_type = "::hilti::rt::Bool"}; }

    void operator()(type::Bitfield* n) final {
        auto x = node::transform(n->bits(true), [this](const auto& b) {
            return cg->compile(b->itemType(), codegen::TypeUsage::Storage);
        });

        auto t = fmt("::hilti::rt::Bitfield<%s>", util::join(x, ", "));
        auto ti = cg->typeInfo(type);
        result = CxxTypes{.base_type = t, .default_ = cxx::Expression(fmt("%s{%s}", t, ti))};
    }

    void operator()(type::Bytes* n) final { result = CxxTypes{.base_type = "::hilti::rt::Bytes"}; }

    void operator()(type::Real* n) final { result = CxxTypes{.base_type = "double"}; }

    void operator()(type::Enum* n) final {
        assert(n->typeID());

        if ( auto cxx = n->cxxID() ) {
            result = CxxTypes{.base_type = cxx::Type(cxx), .default_ = cxx::Expression(cxx::ID(cxx, "Undef"))};
            return;
        }

        auto tid = n->typeID();
        assert(tid);

        auto scope = cxx::ID{cg->unit()->cxxInternalNamespace()};
        auto sid = cxx::ID{tid};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        // Add tailored to_string() function.
        auto cases = util::transform(n->uniqueLabels(), [&](auto l) {
            auto b = cxx::Block();
            b.addReturn(fmt("\"%s::%s\"", tid.local(), l->id()));
            return std::make_pair(cxx::Expression(cxx::ID(id, l->id())), std::move(b));
        });

        auto default_ = cxx::Block();
        default_.addReturn(fmt(R"(::hilti::rt::fmt("%s::<unknown-%%" PRIu64 ">", x.value()))", id.local()));

        auto body = cxx::Block();
        body.addSwitch("x.value()", cases, std::move(default_));

        auto ts = cxx::declaration::Function(cxx::declaration::Function::Free, "std::string",
                                             {"::hilti::rt::detail::adl", "to_string"},
                                             {cxx::declaration::Argument("x", cxx::Type(id)),
                                              cxx::declaration::Argument("", "adl::tag")},
                                             "inline", std::move(body));

        cg->unit()->add(ts);

        // Add tailored operator<<.
        auto render_body = cxx::Block();
        render_body.addStatement("o << ::hilti::rt::to_string(x); return o");

        auto render = cxx::declaration::Function(cxx::declaration::Function::Free, "std::ostream&",
                                                 cxx::ID{fmt("%s::operator<<", id.namespace_())},
                                                 {cxx::declaration::Argument("o", "std::ostream&"),
                                                  cxx::declaration::Argument("x", cxx::Type(id.local()))},
                                                 "inline", std::move(render_body));
        cg->unit()->add(render);

        result = CxxTypes{.base_type = std::string(sid), .default_ = cxx::Expression(cxx::ID(sid, "Undef"))};
    }

    void operator()(type::Error* n) final { result = CxxTypes{.base_type = "::hilti::rt::result::Error"}; }

    void operator()(type::Exception* n) final {
        if ( auto cxx = n->cxxID() ) {
            result = CxxTypes{.base_type = cxx::Type(cxx)};
            return;
        }

        if ( auto id = n->typeID() ) {
            result = CxxTypes{.base_type = std::string(id), .storage = "::hilti::rt::Exception"};
            return;
        }
        else
            result = CxxTypes{.base_type = "::hilti::rt::Exception"};
    }

    void operator()(type::Function* n) final { result = CxxTypes{}; }

    void operator()(type::Interval* n) final { result = CxxTypes{.base_type = "::hilti::rt::Interval"}; }

    void operator()(type::bytes::Iterator* n) final {
        result = CxxTypes{.base_type = "::hilti::rt::bytes::SafeIterator"};
    }

    void operator()(type::stream::Iterator* n) final {
        result = CxxTypes{.base_type = "::hilti::rt::stream::SafeConstIterator"};
    }

    void operator()(type::list::Iterator* n) final {
        auto [cxx_type, _] = cg->cxxTypeForVector(n->dereferencedType(), true);
        result = CxxTypes{.base_type = cxx_type};
    }

    void operator()(type::map::Iterator* n) final {
        const auto* i = (n->dereferencedType()->isConstant() ? "const_iterator" : "iterator");
        auto k = cg->compile(n->keyType(), codegen::TypeUsage::Storage);
        auto v = cg->compile(n->valueType(), codegen::TypeUsage::Storage);

        auto t = fmt("::hilti::rt::Map<%s, %s>::%s", k, v, i);
        result = CxxTypes{.base_type = fmt("%s", t)};
    }

    void operator()(type::set::Iterator* n) final {
        const auto* i = (n->dereferencedType()->isConstant() ? "const_iterator" : "iterator");
        auto x = cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage);

        auto t = fmt("::hilti::rt::Set<%s>::%s", x, i);
        result = CxxTypes{.base_type = fmt("%s", t)};
    }


    void operator()(type::vector::Iterator* n) final {
        auto [cxx_type, _] = cg->cxxTypeForVector(n->dereferencedType(), true);
        result = CxxTypes{.base_type = cxx_type};
    }

    void operator()(type::Library* n) final {
        result = CxxTypes{.base_type = fmt("%s%s", (n->isConstant() ? "const " : ""), n->cxxName()),
                          .param_in = fmt("const %s %s &", n->cxxName(), (n->isConstant() ? "const " : ""))};
    }

    void operator()(type::List* n) final {
        if ( n->elementType()->type()->isA<type::Unknown>() )
            // Can only be the empty list.
            result = CxxTypes{.base_type = "::hilti::rt::list::Empty"};
        else {
            auto [cxx_type, _] = cg->cxxTypeForVector(n->elementType());
            result = CxxTypes{.base_type = cxx_type};
        }
    }

    void operator()(type::Map* n) final {
        std::string t;

        if ( n->elementType()->type()->isA<type::Unknown>() )
            // Can only be the empty map.
            t = "::hilti::rt::map::Empty";
        else {
            auto k = cg->compile(n->keyType(), codegen::TypeUsage::Storage);
            auto v = cg->compile(n->elementType(), codegen::TypeUsage::Storage);
            t = fmt("::hilti::rt::Map<%s, %s>", k, v);
        }

        result = CxxTypes{.base_type = fmt("%s", t)};
    }

    void operator()(type::Network* n) final { result = CxxTypes{.base_type = "::hilti::rt::Network"}; }

    void operator()(type::Null* n) final { result = CxxTypes{.base_type = "::hilti::rt::Null"}; }

    void operator()(type::Port* n) final { result = CxxTypes{.base_type = "::hilti::rt::Port"}; }

    void operator()(type::RegExp* n) final { result = CxxTypes{.base_type = "::hilti::rt::RegExp"}; }

    void operator()(type::SignedInteger* n) final {
        cxx::Type t;

        switch ( n->width() ) {
            case 8: t = "::hilti::rt::integer::safe<int8_t>"; break;
            case 16: t = "::hilti::rt::integer::safe<int16_t>"; break;
            case 32: t = "::hilti::rt::integer::safe<int32_t>"; break;
            case 64: t = "::hilti::rt::integer::safe<int64_t>"; break;
            default: logger().internalError("codegen: unexpected integer width", n);
        }

        result = CxxTypes{.base_type = t};
    }

    void operator()(type::Set* n) final {
        std::string t;

        if ( n->elementType()->type()->isA<type::Unknown>() )
            // Can only be the empty list.
            t = "::hilti::rt::set::Empty";
        else {
            auto x = cg->compile(n->elementType(), codegen::TypeUsage::Storage);
            t = fmt("::hilti::rt::Set<%s>", x);
        }

        result = CxxTypes{.base_type = fmt("%s", t)};
    }

    void operator()(type::Stream* n) final { result = CxxTypes{.base_type = "::hilti::rt::Stream"}; }

    void operator()(type::Type_* n) final {
        assert(n->typeValue());
        dispatch(n->typeValue()->type());
    }

    void operator()(type::Union* n) final {
        assert(n->typeID());

        if ( auto x = n->cxxID() ) {
            result = CxxTypes{.base_type = cxx::Type(x)};
            return;
        }

        auto scope = cxx::ID{cg->unit()->cxxInternalNamespace().namespace_()};
        auto sid = cxx::ID{scope, n->typeID()};
        auto ns = sid.namespace_();

        result = cache->getOrCreate(
            sid, [&]() { return CxxTypes{.base_type = std::string(sid)}; },
            [&](auto& cxx_types) {
                auto render_body = cxx::Block();
                render_body.addStatement("o << ::hilti::rt::to_string(x); return o");

                auto render = cxx::declaration::Function(cxx::declaration::Function::Free, "std::ostream&",
                                                         cxx::ID{fmt("%s::operator<<", ns)},
                                                         {cxx::declaration::Argument("o", "std::ostream&"),
                                                          cxx::declaration::Argument("x", fmt("const %s&", sid))},
                                                         "extern", std::move(render_body));
                cg->unit()->add(render);

                return cxx_types;
            });
    }

    void operator()(type::Vector* n) final {
        if ( n->elementType()->type()->isA<type::Unknown>() )
            // Can only be the empty list.
            result = CxxTypes{.base_type = "::hilti::rt::vector::Empty"};
        else {
            auto [cxx_type, _] = cg->cxxTypeForVector(n->elementType());
            result = CxxTypes{.base_type = cxx_type};
        }
    }

    void operator()(type::Time* n) final { result = CxxTypes{.base_type = "::hilti::rt::Time"}; }

    void operator()(type::UnsignedInteger* n) final {
        cxx::Type t;

        switch ( n->width() ) {
            case 8:
                t = "::hilti::rt::integer::safe<uint8_t>";
                break; // 2 bytes to avoid overloading confusion with uchar_t
            case 16: t = "::hilti::rt::integer::safe<uint16_t>"; break;
            case 32: t = "::hilti::rt::integer::safe<uint32_t>"; break;
            case 64: t = "::hilti::rt::integer::safe<uint64_t>"; break;
            default: logger().internalError("codegen: unexpected integer width", n);
        }

        result = CxxTypes{.base_type = t};
    }

    void operator()(type::Optional* n) final {
        std::string t;

        if ( const auto& ct = n->dereferencedType(); ! ct->isWildcard() )
            t = fmt("::hilti::rt::Optional<%s>", cg->compile(ct, codegen::TypeUsage::Storage));
        else
            t = "*";

        result = CxxTypes{.base_type = t};
    }

    void operator()(type::StrongReference* n) final {
        std::string t;

        if ( const auto& ct = n->dereferencedType(); ! ct->isWildcard() )
            t = fmt("::hilti::rt::StrongReference<%s>", cg->compile(ct, codegen::TypeUsage::Ctor)); // XXX
        else
            t = "*";

        result = CxxTypes{.base_type = t, .param_in = fmt("%s", t), .param_inout = fmt("%s&", t)};
    }

    void operator()(type::stream::View* n) final { result = CxxTypes{.base_type = "::hilti::rt::stream::View"}; }

    void operator()(type::Result* n) final {
        std::string t;

        if ( const auto& ct = n->dereferencedType(); ! ct->isWildcard() ) {
            if ( ct->type()->isA<type::Void>() )
                t = "::hilti::rt::Result<::hilti::rt::Nothing>";
            else
                t = fmt("::hilti::rt::Result<%s>", cg->compile(ct, codegen::TypeUsage::Storage));
        }
        else
            t = "*";

        result = CxxTypes{.base_type = t};
    }

    void operator()(type::String* n) final { result = CxxTypes{.base_type = "std::string"}; }

    void operator()(type::Struct* n) final {
        auto type_id = n->typeID();
        if ( ! type_id ) {
            // Special-case: construct a type ID for anonymous structs.
            auto* ctor = n->parent(2)->tryAs<ctor::Struct>();
            auto* decl = n->parent<declaration::Type>();
            if ( ctor && decl )
                type_id = decl->fullyQualifiedID() + ctor->uniqueID();
        }

        assert(type_id);

        if ( auto x = n->cxxID() ) {
            result = CxxTypes{.base_type = cxx::Type(x)};
            return;
        }

        auto scope = cxx::ID{cg->unit()->cxxInternalNamespace().namespace_()};
        auto sid = cxx::ID{scope, type_id};
        auto ns = sid.namespace_();

        result = cache->getOrCreate(
            sid, [&]() { return CxxTypes{.base_type = std::string(sid)}; },
            [&](auto& cxx_types) {
                auto render_body = cxx::Block();
                render_body.addStatement("return o << ::hilti::rt::to_string(x);");

                auto render = cxx::declaration::Function(cxx::declaration::Function::Free, "std::ostream&",
                                                         cxx::ID{fmt("%s::operator<<", ns)},
                                                         {cxx::declaration::Argument("o", "std::ostream&"),
                                                          cxx::declaration::Argument("x", fmt("const %s&", sid))},
                                                         "extern", std::move(render_body));
                cg->unit()->add(render);

                return cxx_types;
            });
    }

    void operator()(type::Tuple* n) final {
        auto types =
            util::join(util::transform(n->elements(),
                                       [this](auto e) { return cg->compile(e->type(), codegen::TypeUsage::Storage); }),
                       ", ");

        auto defaults =
            util::join(util::transform(n->elements(),
                                       [this](auto e) {
                                           if ( auto d = cg->typeDefaultValue(e->type()) )
                                               // Engage the optional with the element's explicit default value.
                                               return fmt("{%s}", *d);
                                           else {
                                               // No explicit default (e.g., Bool, integers, etc.).
                                               // If the element type itself is an Optional<T>, leave it unset.
                                               if ( e->type()->type()->template isA<type::Optional>() )
                                                   return fmt("::hilti::rt::optional::make<%s>({})",
                                                              cg->compile(e->type(), codegen::TypeUsage::Storage));

                                               // Otherwise engage the optional with a value-initialized T{} so
                                               // required (non-optional) tuple elements start as set.
                                               auto t = cg->compile(e->type(), codegen::TypeUsage::Storage);
                                               return fmt("::hilti::rt::Optional<%s>(%s{})", t, t);
                                           }
                                       }),
                       ", ");

        auto base_type = fmt("::hilti::rt::Tuple<%s>", types);
        auto default_ = fmt("::hilti::rt::tuple::make_from_optionals<%s>(%s)", types, defaults);
        result = CxxTypes{.base_type = base_type, .default_ = default_};
    }

    void operator()(type::Name* n) final {
        assert(n->resolvedType());
        dispatch(n->resolvedType());
    }

    void operator()(type::Void* n) final { result = CxxTypes{.base_type = "void"}; }

    void operator()(type::Auto* n) final { logger().internalError("codegen: automatic type has not been replaced"); }

    void operator()(type::WeakReference* n) final {
        std::string t;

        if ( const auto& ct = n->dereferencedType(); ! ct->isWildcard() )
            t = fmt("::hilti::rt::WeakReference<%s>", cg->compile(ct, codegen::TypeUsage::Ctor));
        else
            t = "*";

        result = CxxTypes{.base_type = t};
    }

    void operator()(type::ValueReference* n) final {
        if ( const auto& ct = n->dereferencedType(); ! ct->isWildcard() ) {
            auto element_type = cg->compile(ct, codegen::TypeUsage::Ctor);
            result = CxxTypes{.base_type = fmt("::hilti::rt::ValueReference<%s>", element_type), .ctor = element_type};
        }
        else
            result = CxxTypes{.base_type = "*"};
    }
};

// Visitor returning the ID of static, predefined type information instances for types that provide it.
struct VisitorTypeInfoPredefined : hilti::visitor::PreOrder {
    VisitorTypeInfoPredefined(CodeGen* cg) : cg(cg) {}

    CodeGen* cg;

    std::optional<cxx::Expression> result;

    void operator()(type::Address* n) final { result = "::hilti::rt::type_info::address"; }
    void operator()(type::Any* n) final { result = "::hilti::rt::type_info::any"; }
    void operator()(type::Bool* n) final { result = "::hilti::rt::type_info::bool_"; }
    void operator()(type::Bytes* n) final { result = "::hilti::rt::type_info::bytes"; }
    void operator()(type::bytes::Iterator* n) final { result = "::hilti::rt::type_info::bytes_iterator"; }
    void operator()(type::Error* n) final { result = "::hilti::rt::type_info::error"; }
    void operator()(type::Interval* n) final { result = "::hilti::rt::type_info::interval"; }
    void operator()(type::Network* n) final { result = "::hilti::rt::type_info::network"; }
    void operator()(type::Null* n) final { result = "::hilti::rt::type_info::null"; }
    void operator()(type::Port* n) final { result = "::hilti::rt::type_info::port"; }
    void operator()(type::Real* n) final { result = "::hilti::rt::type_info::real"; }
    void operator()(type::RegExp* n) final { result = "::hilti::rt::type_info::regexp"; }
    void operator()(type::SignedInteger* n) final { result = fmt("::hilti::rt::type_info::int%d", n->width()); }
    void operator()(type::Stream* n) final { result = "::hilti::rt::type_info::stream"; }
    void operator()(type::stream::Iterator* n) final { result = "::hilti::rt::type_info::stream_iterator"; }
    void operator()(type::stream::View* n) final { result = "::hilti::rt::type_info::stream_view"; }
    void operator()(type::String* n) final { result = "::hilti::rt::type_info::string"; }
    void operator()(type::Time* n) final { result = "::hilti::rt::type_info::time"; }
    void operator()(type::UnsignedInteger* n) final { result = fmt("::hilti::rt::type_info::uint%d", n->width()); }
    void operator()(type::Void* n) final { result = "::hilti::rt::type_info::void_"; }

    void operator()(type::Auto* n) final { logger().internalError("codegen: automatic type has not been replaced"); }
    void operator()(type::Name* n) final {
        assert(n->resolvedType());
        dispatch(n->resolvedType());
    }
};

// Visitor creating dynamic type information instances for types that do not provide predefined static ones.
struct VisitorTypeInfoDynamic : hilti::visitor::PreOrder {
    VisitorTypeInfoDynamic(CodeGen* cg, QualifiedType* type) : cg(cg), type(type) {}

    CodeGen* cg;
    QualifiedType* type = nullptr;

    std::optional<cxx::Expression> result;

    void operator()(type::Bitfield* n) final {
        std::vector<QualifiedType*> types;
        for ( const auto& b : n->bits(true) ) {
            auto* itype = b->itemType();
            types.emplace_back(itype);
        }

        auto tuple_ti = cg->typeInfo(cg->builder()->qualifiedType(cg->builder()->typeTuple(types), Constness::Const));

        std::vector<std::string> elems;
        auto ttype = cg->compile(type, codegen::TypeUsage::Storage);

        for ( const auto&& b : n->bits() )
            elems.push_back(fmt("::hilti::rt::type_info::bitfield::Bits{ \"%s\", %u, %u, %s }", b->id(), b->lower(),
                                b->upper(), cg->typeInfo(b->itemType())));

        result =
            fmt("::hilti::rt::type_info::Bitfield(%u, std::vector<::hilti::rt::type_info::bitfield::Bits>({%s}), %s)",
                n->width(), util::join(elems, ", "), tuple_ti);
    }

    void operator()(type::Enum* n) final {
        std::vector<std::string> labels;

        for ( const auto& l : n->labels() )
            labels.push_back(fmt("::hilti::rt::type_info::enum_::Label{ \"%s\", %d }", cxx::ID(l->id()), l->value()));

        result = fmt("::hilti::rt::type_info::Enum(std::vector<::hilti::rt::type_info::enum_::Label>({%s}))",
                     util::join(labels, ", "));
    }

    void operator()(type::Exception* n) final { result = "::hilti::rt::type_info::Exception()"; }

    void operator()(type::Function* n) final { result = "::hilti::rt::type_info::Function()"; }

    void operator()(type::Library* n) final { result = fmt("::hilti::rt::type_info::Library(\"%s\")", n->cxxName()); }

    // Helper factoring out common logic for creating type information for
    // vectors and vector iterators.
    std::string typeInfoForVector(QualifiedType* element_type, bool want_iterator = false) {
        auto etype = cg->compile(element_type, codegen::TypeUsage::Storage);
        const auto* type_name = (want_iterator ? "VectorIterator" : "Vector");

        std::string type_addl;

        if ( want_iterator )
            type_addl = (element_type->isConstant() ? "::const_iterator" : "::iterator");

        if ( auto default_ = cg->typeDefaultValue(element_type) )
            return fmt(
                "::hilti::rt::type_info::%s(%s, ::hilti::rt::type_info::%s::accessor<%s, "
                "::hilti::rt::vector::Allocator<%s>>())",
                type_name, cg->typeInfo(element_type), type_name, etype, etype);
        else
            return fmt("::hilti::rt::type_info::%s(%s, ::hilti::rt::type_info::%s::accessor<%s>())", type_name,
                       cg->typeInfo(element_type), type_name, etype);
    }

    void operator()(type::List* n) final {
        // This generates type information for a vector, as that's how we store lists.
        result = typeInfoForVector(n->elementType());
    }

    void operator()(type::Map* n) final {
        auto ktype = cg->compile(n->keyType(), codegen::TypeUsage::Storage);
        auto vtype = cg->compile(n->elementType(), codegen::TypeUsage::Storage);
        result = fmt("::hilti::rt::type_info::Map(%s, %s, ::hilti::rt::type_info::Map::accessor<%s, %s>())",
                     cg->typeInfo(n->keyType()), cg->typeInfo(n->elementType()),
                     cg->compile(n->keyType(), codegen::TypeUsage::Storage),
                     cg->compile(n->elementType(), codegen::TypeUsage::Storage));
    }

    void operator()(type::map::Iterator* n) final {
        result =
            fmt("::hilti::rt::type_info::MapIterator(%s, %s, ::hilti::rt::type_info::MapIterator::accessor<%s, %s>())",
                cg->typeInfo(n->keyType()), cg->typeInfo(n->valueType()),
                cg->compile(n->keyType(), codegen::TypeUsage::Storage),
                cg->compile(n->valueType(), codegen::TypeUsage::Storage));
    }

    void operator()(type::Optional* n) final {
        result =
            fmt("::hilti::rt::type_info::Optional(%s, ::hilti::rt::type_info::Optional::accessor<%s>())",
                cg->typeInfo(n->dereferencedType()), cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage));
    }

    void operator()(type::Result* n) final {
        if ( ! n->dereferencedType()->type()->isA<type::Void>() )
            result = fmt("::hilti::rt::type_info::Result(%s, ::hilti::rt::type_info::Result::accessor<%s>())",
                         cg->typeInfo(n->dereferencedType()),
                         cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage));
        else
            result = fmt("::hilti::rt::type_info::Result(%s, {})", cg->typeInfo(n->dereferencedType()));
    }

    void operator()(type::Set* n) final {
        result = fmt("::hilti::rt::type_info::Set(%s, ::hilti::rt::type_info::Set::accessor<%s>())",
                     cg->typeInfo(n->elementType()), cg->compile(n->elementType(), codegen::TypeUsage::Storage));
    }

    void operator()(type::set::Iterator* n) final {
        result =
            fmt("::hilti::rt::type_info::SetIterator(%s, ::hilti::rt::type_info::SetIterator::accessor<%s>())",
                cg->typeInfo(n->dereferencedType()), cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage));
    }

    void operator()(type::Struct* n) final {
        std::vector<std::string> fields;

        for ( const auto& f : n->fields() ) {
            if ( f->type()->type()->isA<type::Function>() )
                continue;

            if ( f->isStatic() )
                continue;

            std::string accessor;

            if ( f->isOptional() && ! f->isNoEmit() )
                accessor = fmt(", ::hilti::rt::type_info::struct_::Field::accessor_optional<%s>()",
                               cg->compile(f->type(), codegen::TypeUsage::Storage));

            cxx::ID cxx_type_id{n->typeID()};
            if ( auto x = n->cxxID() )
                cxx_type_id = x;

            std::string offset;

            if ( ! f->isNoEmit() )
                offset = fmt("static_cast<std::ptrdiff_t>(offsetof(%s, %s))", cxx_type_id, cxx::ID(f->id()));
            else
                offset = "std::ptrdiff_t{-1}";

            fields.push_back(fmt("::hilti::rt::type_info::struct_::Field{ \"%s\", %s, %s, %s, %s, %s%s }", f->id(),
                                 cg->typeInfo(f->type()), offset, f->isInternal(), f->isAnonymous(), ! f->isNoEmit(),
                                 accessor));
        }

        result = fmt("::hilti::rt::type_info::Struct(std::vector<::hilti::rt::type_info::struct_::Field>({%s}))",
                     util::join(fields, ", "));
    }

    void operator()(type::Tuple* n) final {
        std::vector<std::string> elems;
        auto ttype = cg->compile(type, codegen::TypeUsage::Storage);

        int i = 0;
        for ( const auto& e : n->elements() ) {
            elems.push_back(fmt("::hilti::rt::type_info::tuple::Element{ \"%s\", %s, %s::elementOffset<%d>() }",
                                e->id() ? e->id() : ID(), cg->typeInfo(e->type()), ttype, i));
            ++i;
        }

        result = fmt("::hilti::rt::type_info::Tuple(std::vector<::hilti::rt::type_info::tuple::Element>({%s}))",
                     util::join(elems, ", "));
    }

    void operator()(type::Union* n) final {
        std::vector<std::string> fields;

        for ( const auto& f : n->fields() )
            fields.push_back(
                fmt("::hilti::rt::type_info::union_::Field{ \"%s\", %s }", cxx::ID(f->id()), cg->typeInfo(f->type())));

        result =
            fmt("::hilti::rt::type_info::Union(std::vector<::hilti::rt::type_info::union_::Field>({%s}), "
                "::hilti::rt::type_info::Union::accessor<%s>())",
                util::join(fields, ", "), cg->compile(type, codegen::TypeUsage::Storage));
    }
    void operator()(type::StrongReference* n) final {
        result =
            fmt("::hilti::rt::type_info::StrongReference(%s, ::hilti::rt::type_info::StrongReference::accessor<%s>())",
                cg->typeInfo(n->dereferencedType()), cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage));
    }

    void operator()(type::ValueReference* n) final {
        result =
            fmt("::hilti::rt::type_info::ValueReference(%s, ::hilti::rt::type_info::ValueReference::accessor<%s>())",
                cg->typeInfo(n->dereferencedType()), cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage));
    }

    void operator()(type::WeakReference* n) final {
        result =
            fmt("::hilti::rt::type_info::WeakReference(%s, ::hilti::rt::type_info::WeakReference::accessor<%s>())",
                cg->typeInfo(n->dereferencedType()), cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage));
    }

    void operator()(type::Vector* n) final { result = typeInfoForVector(n->elementType()); }

    void operator()(type::vector::Iterator* n) final { result = typeInfoForVector(n->dereferencedType(), true); }

    void operator()(type::Name* n) final {
        assert(n->resolvedTypeIndex());
        dispatch(n->resolvedType());
    }

    void operator()(type::Auto* n) final { logger().internalError("codegen: automatic type has not been replaced"); }
};

} // anonymous namespace

cxx::Type CodeGen::compile(QualifiedType* t, codegen::TypeUsage usage) {
    auto v = VisitorStorage(this, t, &_cache_types_storage, usage);
    auto x = hilti::visitor::dispatch(v, t->type(), [](const auto& v) -> const auto& { return v.result; });
    if ( ! x ) {
        std::cerr << t->dump();
        logger().internalError(fmt("codegen: type %s does not have a visitor", *t), t);
    }

    std::optional<cxx::Type> base_type;
    if ( x->base_type && usage != codegen::TypeUsage::Ctor )
        base_type = *x->base_type;

    switch ( usage ) {
        case codegen::TypeUsage::Storage:
            if ( x->storage )
                return std::move(*x->storage);

            if ( base_type )
                return std::move(*base_type);

            logger().internalError(fmt("codegen: type %s does not support use as storage (%s)", t->type()->renderSelf(),
                                       t->type()->typename_()),
                                   t);
            break;

        case codegen::TypeUsage::CopyParameter:
            if ( x->param_copy )
                return std::move(*x->param_copy);

            if ( base_type )
                return fmt("%s", *base_type);

            logger().internalError(fmt("codegen: type %s does not support use as copy-parameter ",
                                       t->type()->renderSelf()),
                                   t);
            break;

        case codegen::TypeUsage::InParameter:
            if ( x->param_in )
                return std::move(*x->param_in);

            if ( base_type )
                return fmt("const %s&", *base_type);

            logger().internalError(fmt("codegen: type %s does not support use as in-parameter ",
                                       t->type()->renderSelf()),
                                   t);
            break;

        case codegen::TypeUsage::InOutParameter:
            if ( x->param_inout )
                return std::move(*x->param_inout);

            if ( base_type )
                return fmt("%s&", *base_type);

            logger().internalError(fmt("codegen: type %s does not support use as inout-parameter ",
                                       t->type()->renderSelf()),
                                   t);
            break;

        case codegen::TypeUsage::FunctionResult:
            if ( x->result )
                return std::move(*x->result);

            if ( base_type )
                return std::move(*base_type);

            logger().internalError(fmt("codegen: type %s does not support use as function result",
                                       t->type()->renderSelf()),
                                   t);
            break;

        case codegen::TypeUsage::Ctor:
            if ( x->ctor )
                return std::move(*x->ctor);

            if ( x->base_type )
                return std::move(*x->base_type);

            logger().internalError(fmt("codegen: type %s does not support use as storage", t->type()->renderSelf()), t);
            break;

        case codegen::TypeUsage::None:
            logger().internalError(fmt("codegen: type compilation with 'None' usage", t->type()->renderSelf()), t);
            break;
        default: util::cannotBeReached();
    }
}

std::optional<cxx::Expression> CodeGen::typeDefaultValue(hilti::QualifiedType* t) {
    auto v = VisitorStorage(this, t, &_cache_types_storage, codegen::TypeUsage::None);
    auto x = hilti::visitor::dispatch(v, t->type(), [](const auto& v) -> const auto& { return v.result; });
    if ( ! x ) {
        std::cerr << t->dump();
        logger().internalError(fmt("codegen: type %s does not have a visitor", *t), t);
    }

    return std::move(x->default_);
}

std::list<cxx::declaration::Type> CodeGen::typeDependencies(QualifiedType* t) {
    VisitorDeclaration v(this, t, &_cache_types_declarations);
    v.dispatch(t->type());
    return v.dependencies;
};

std::optional<cxx::declaration::Type> CodeGen::typeDeclaration(QualifiedType* t) {
    if ( t->type()->cxxID() )
        return {};

    auto v = VisitorDeclaration(this, t, &_cache_types_declarations);
    return hilti::visitor::dispatch(v, t->type(), [](const auto& v) -> const auto& { return v.result; });
};

const CxxTypeInfo& CodeGen::_getOrCreateTypeInfo(QualifiedType* t) {
    std::stringstream display;

    if ( t->type()->typeID() )
        // Prefer the bare type name as the display value.
        display << t->type()->typeID();
    else
        printer::print(display, t, true, true);

    if ( display.str().empty() )
        logger().internalError(fmt("codegen: type %s does not have a display rendering for type information",
                                   t->type()->typename_()),
                               t);

    // Each module contains all the type information it needs. We put the
    // declarations into an anonymous namespace so that they won't be
    // externally visible.
    cxx::ID tid(options().cxx_namespace_intern, "type_info", "",
                fmt("__ti_%s_%s", util::toIdentifier(display.str()), util::toIdentifier(t->type()->unification())));

    return _cache_type_info.getOrCreate(
        tid,
        [&]() {
            auto v = VisitorTypeInfoPredefined(this);

            if ( auto x = hilti::visitor::dispatch(v, t->type(), [](const auto& v) -> const auto& { return v.result; });
                 x && *x )
                return CxxTypeInfo{.predefined = true, .reference = fmt("&%s", *x)};

            auto forward = cxx::declaration::Constant(tid, "::hilti::rt::TypeInfo", {}, "extern");
            unit()->add(forward);

            return CxxTypeInfo{.predefined = false,
                               .reference = fmt("&%s", std::string(ID("type_info", tid.local()))),
                               .forward = forward};
        },
        [&](auto& ti) {
            if ( ti.predefined )
                return ti;

            auto v = VisitorTypeInfoDynamic(this, t);
            auto x = hilti::visitor::dispatch(v, t->type(), [](const auto& v) -> const auto& { return v.result; });
            if ( ! x )
                logger().internalError(fmt("codegen: type %s does not have a dynamic type info visitor", *t), t);

            const auto& id_init = (t->type()->typeID() ? fmt("\"%s\"", t->type()->typeID()) : std::string("{}"));

            std::string to_string;

            if ( auto* x = t->type()->tryAs<type::Library>() )
                // Library types cannot be rendered into strings, just hardcode the type's name.
                to_string = fmt("[](const void *self) { return \"<%s>\"s; }", x->cxxName());
            else
                to_string =
                    fmt("[](const void *self) { return hilti::rt::to_string(*reinterpret_cast<const %s*>(self)); }",
                        compile(t, codegen::TypeUsage::Storage));

            auto init = fmt("{ %s, \"%s\", %s, new %s }", id_init,
                            util::escapeUTF8(display.str(), util::render_style::UTF8::EscapeQuotes), to_string, *x);

            ti.declaration = cxx::declaration::Constant(tid, "::hilti::rt::TypeInfo", init, "");

            unit()->add(*ti.declaration);

            return ti;
        });
}

cxx::Expression CodeGen::_makeLhs(cxx::Expression expr, QualifiedType* type) {
    if ( expr.isLhs() )
        return expr;

    auto tmp = addTmp("lhs", compile(type, TypeUsage::Storage));
    cxx::Expression result;

    if ( type->type()->isA<type::ValueReference>() )
        result = cxx::Expression{fmt("(%s=(%s).asSharedPtr())", tmp, expr), Side::LHS}; // avoid copy
    else
        result = cxx::Expression{fmt("(%s=(%s))", tmp, expr), Side::LHS};

    // This can help show where LHS conversions happen unexpectedly; they
    // should be very rare.
    HILTI_DEBUG(logging::debug::CodeGen, fmt("RHS -> LHS: %s -> %s [%s]", expr, result, type->typename_()));

    return result;
}

cxx::Expression CodeGen::typeInfo(QualifiedType* t) { return _getOrCreateTypeInfo(t).reference; };

void CodeGen::addTypeInfoDefinition(QualifiedType* t) { _getOrCreateTypeInfo(t); }
