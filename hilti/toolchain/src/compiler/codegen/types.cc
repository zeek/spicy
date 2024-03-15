// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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
        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{n->typeID()};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        result = cache->getOrCreate(
            id,
            []() {
                // Just return an empty dummy for now to avoid cyclic recursion.
                return cxx::declaration::Type{};
            },
            [&](auto& dummy) {
                std::vector<cxx::declaration::Argument> args;
                std::vector<cxx::type::struct_::Member> fields;

                cxx::Block ctor;

                cxx::Block self_body;
                self_body.addStatement(util::fmt("return ::hilti::rt::ValueReference<%s>::self(this)", id));

                auto self = cxx::declaration::Function{.result = "auto",
                                                       .id = "__self",
                                                       .args = {},
                                                       .linkage = "inline",
                                                       .inline_body = std::move(self_body)};

                fields.emplace_back(std::move(self));

                cg->enablePrioritizeTypes();

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
                    if ( auto x = p->default_() )
                        default_ = cg->compile(x);
                    else
                        default_ = cg->typeDefaultValue(p->type());

                    auto arg = cxx::declaration::Argument{.id = cxx::ID(fmt("__p_%s", p->id())),
                                                          .type = type,
                                                          .default_ = std::move(default_),
                                                          .internal_type = internal_type};
                    args.emplace_back(std::move(arg));
                }

                for ( const auto& f : n->fields() ) {
                    if ( f->isNoEmit() )
                        continue;

                    if ( auto ft = f->type()->type()->tryAs<type::Function>() ) {
                        auto d = cg->compile(f->id(), ft, declaration::Linkage::Struct,
                                             function::CallingConvention::Standard, f->attributes());

                        if ( f->isStatic() )
                            d.linkage = "static";

                        if ( auto func = f->inlineFunction(); func && func->body() ) {
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
                                auto self = cxx::declaration::Local{"__self", "auto", {}, fmt("%s::__self()", id_type)};
                                cxx_body.addLocal(self);
                            }

                            cg->compile(func->body(), &cxx_body);

                            auto method_impl = cxx::Function{.declaration = d, .body = std::move(cxx_body)};
                            method_impl.declaration.id = cxx::ID(scope, sid, f->id());
                            method_impl.declaration.linkage = "inline";
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
                            auto self = cxx::declaration::Local{"__self", "auto", {}, fmt("%s::__self()", id_type)};
                            method_body.addLocal(self);
                            method_body.addStatement(fmt("return %s(%s)", id_hook, util::join(args, ", ")));

                            auto method_impl = cxx::Function{.declaration = d, .body = std::move(method_body)};

                            method_impl.declaration.id = cxx::ID(scope, sid, f->id());
                            method_impl.declaration.linkage = "inline";
                            cg->unit()->add(method_impl);

                            std::list<cxx::declaration::Type> aux_types = {
                                cxx::declaration::Type{cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                                       fmt("struct %s", id_class),
                                                       {},
                                                       true}};

                            for ( const auto& p : ft->parameters() ) {
                                for ( auto t : cg->typeDependencies(p->type()) )
                                    aux_types.push_back(std::move(t));
                            }

                            auto hook = cxx::linker::Join{.id = cxx::ID(id_hook),
                                                          .callee = d,
                                                          .aux_types = aux_types,
                                                          .declare_only = true};

                            auto vref =
                                cg->builder()->qualifiedType(cg->builder()->typeValueReference(type), Constness::Const);
                            // NOLINTNEXTLINE(modernize-use-emplace)
                            hook.callee.args.push_back(
                                cxx::declaration::Argument{.id = "__self",
                                                           .type =
                                                               cg->compile(vref, codegen::TypeUsage::InOutParameter)});
                            cg->unit()->add(hook);
                        }

                        fields.emplace_back(std::move(d));
                        continue;
                    }

                    auto t = cg->compile(f->type(), codegen::TypeUsage::Storage);

                    if ( f->isOptional() )
                        t = fmt("std::optional<%s>", t);

                    std::optional<cxx::Expression> default_;

                    // Push a block so all values needed to default-initialize
                    // fields have a block. This is required if compiling the
                    // value needs to e.g., create temporaries.
                    cg->pushCxxBlock(&ctor);

                    if ( ! f->isOptional() ) {
                        cg->pushSelf("__self()");
                        if ( auto x = f->default_() )
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
                    auto x =
                        cxx::declaration::Local{cxx::ID(f->id()), t, {}, {}, (f->isStatic() ? "inline static" : "")};


                    fields.emplace_back(std::move(x));
                }

                if ( n->hasFinalizer() ) {
                    // Call the finalizer hook from a C++ destructor.
                    cxx::Block dtor_body;
                    dtor_body.addStatement("_0x7e_finally()");

                    auto dtor = cxx::declaration::Function{.result = "",
                                                           .id = cxx::ID::fromNormalized(
                                                               fmt("~%s", id.local())), // don't escape the ~
                                                           .args = {},
                                                           .linkage = "inline",
                                                           .inline_body = std::move(dtor_body)};

                    fields.emplace_back(std::move(dtor));
                }

                cg->disablePrioritizeTypes();

                // Also add a forward declaration.
                auto type_forward = cxx::declaration::Type{
                    id, fmt("struct %s", id), {}, true, true,
                };

                cg->unit()->add(type_forward);
                dependencies.push_back(type_forward);

                auto t = cxx::type::Struct{.args = std::move(args),
                                           .members = std::move(fields),
                                           .type_name = cxx::ID(id.local()),
                                           .ctor = std::move(ctor),
                                           .add_ctors = true};
                return cxx::declaration::Type{id, t, t.inlineCode()};
            });
    }

    void operator()(type::Tuple* n) final {
        for ( const auto& e : n->elements() )
            addDependency(e->type());
    }

    void operator()(type::Union* n) final {
        assert(n->typeID());

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{n->typeID()};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        // Add a forward declaration.
        auto type_forward = cxx::declaration::Type{id, fmt("struct %s", id.local()), {}, true, true};

        cg->unit()->add(type_forward);
        dependencies.push_back(type_forward);

        std::vector<cxx::type::union_::Member> fields;
        for ( const auto& f : n->fields() ) {
            auto t = cg->compile(f->type(), codegen::TypeUsage::Storage);
            auto x = cxx::declaration::Local{cxx::ID(f->id()), t};
            fields.emplace_back(std::move(x));
        }

        auto t = cxx::type::Union{.members = std::move(fields), .type_name = cxx::ID(id.local())};
        result = cxx::declaration::Type{id, t};
    }

    void operator()(type::Vector* n) final {
        if ( n->elementType()->type()->isA<type::Unknown>() )
            addDependency(n->elementType());
    }

    void operator()(type::Enum* n) final {
        assert(n->typeID());

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{n->typeID()};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        // We declare the full enum type as part of the forward declarations block, that makes sure it's always fully
        // available. This is e.g., needed so we can set default values for vectors of enums.
        auto id = cxx::ID(scope, sid);
        auto labels = util::transform(n->labels(), [](auto l) { return std::make_pair(cxx::ID(l->id()), l->value()); });
        auto t = cxx::type::Enum{.labels = std::move(labels), .type_name = cxx::ID(id.local())};
        auto decl = cxx::declaration::Type{id, t, {}, true, false, true};
        dependencies.push_back(decl);
        result = decl;
    }

    void operator()(type::Exception* n) final {
        assert(n->typeID());

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{n->typeID()};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        std::string base_ns = "::hilti::rt";
        std::string base_cls = "UsageError";

        if ( auto b = n->baseType() ) {
            auto x = cxx::ID(cg->compile(cg->builder()->qualifiedType(b, Constness::Const), codegen::TypeUsage::Ctor));
            base_ns = x.namespace_();
            base_cls = x.local();
        }

        auto id = cxx::ID(scope, sid);

        // Exception instances all need an implementation of a virtual
        // destructor to trigger generation of their vtable.
        auto decl = cxx::declaration::Function{.result = "",
                                               .id = cxx::ID::fromNormalized(fmt("%s::~%s", id, id.local())),
                                               .args = {},
                                               .linkage = "inline"};
        auto func = cxx::Function{.declaration = std::move(decl), .body = cxx::Block()};
        cg->unit()->add(func);

        result = cxx::declaration::Type(id, fmt("HILTI_EXCEPTION_NS(%s, %s, %s)", id.local(), base_ns, base_cls), {},
                                        false, false, true);
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

        auto t = fmt("hilti::rt::Bitfield<%s>", util::join(x, ", "));
        result = CxxTypes{.base_type = t};
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

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
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
        default_.addReturn(fmt(R"(hilti::rt::fmt("%s::<unknown-%%" PRIu64 ">", x.value()))", id.local()));

        auto body = cxx::Block();
        body.addSwitch("x.value()", cases, std::move(default_));

        auto ts_decl = cxx::declaration::Function{.result = "std::string",
                                                  .id = {"::hilti::rt::detail::adl", "to_string"},
                                                  .args = {cxx::declaration::Argument{.id = "x", .type = cxx::Type(id)},
                                                           cxx::declaration::Argument{.id = "", .type = "adl::tag"}},
                                                  .linkage = "inline"};

        auto ts_impl = cxx::Function{.declaration = ts_decl, .body = std::move(body)};

        cg->unit()->add(ts_decl);
        cg->unit()->add(ts_impl);

        // Add tailored operator<<.
        auto render_body = cxx::Block();
        render_body.addStatement("o << ::hilti::rt::to_string(x); return o");

        auto render_decl =
            cxx::declaration::Function{.result = "std::ostream&",
                                       .id = cxx::ID{fmt("%s::operator<<", id.namespace_())},
                                       .args = {cxx::declaration::Argument{.id = "o", .type = "std::ostream&"},
                                                cxx::declaration::Argument{.id = "x", .type = cxx::Type(id.local())}},
                                       .linkage = "inline"};

        auto render_impl = cxx::Function{.declaration = render_decl, .body = std::move(render_body)};

        cg->unit()->add(render_decl);
        cg->unit()->add(render_impl);

        cg->addDeclarationFor(type);
        result = CxxTypes{.base_type = std::string(sid), .default_ = cxx::Expression(cxx::ID(sid, "Undef"))};
    }

    void operator()(type::Error* n) final { result = CxxTypes{.base_type = "::hilti::rt::result::Error"}; }

    void operator()(type::Exception* n) final {
        if ( auto cxx = n->cxxID() ) {
            result = CxxTypes{.base_type = cxx::Type(cxx)};
            return;
        }

        if ( auto id = n->typeID() ) {
            cg->addDeclarationFor(type);
            result = CxxTypes{.base_type = std::string(id), .storage = "::hilti::rt::Exception"};
            return;
        }
        else
            result = CxxTypes{.base_type = "::hilti::rt::Exception"};
    }

    void operator()(type::Function* n) final { result = CxxTypes{}; }

    void operator()(type::Interval* n) final { result = CxxTypes{.base_type = "::hilti::rt::Interval"}; }

    void operator()(type::bytes::Iterator* n) final { result = CxxTypes{.base_type = "::hilti::rt::bytes::Iterator"}; }

    void operator()(type::stream::Iterator* n) final {
        result = CxxTypes{.base_type = "::hilti::rt::stream::SafeConstIterator"};
    }

    void operator()(type::list::Iterator* n) final {
        auto t =
            fmt("::hilti::rt::Vector<%s>::iterator_t", cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage));
        result = CxxTypes{.base_type = fmt("%s", t)};
    }

    void operator()(type::map::Iterator* n) final {
        auto i = (n->dereferencedType()->isConstant() ? "const_iterator" : "iterator");
        auto k = cg->compile(n->keyType(), codegen::TypeUsage::Storage);
        auto v = cg->compile(n->valueType(), codegen::TypeUsage::Storage);

        auto t = fmt("::hilti::rt::Map<%s, %s>::%s", k, v, i);
        result = CxxTypes{.base_type = fmt("%s", t)};
    }

    void operator()(type::set::Iterator* n) final {
        auto i = (n->dereferencedType()->isConstant() ? "const_iterator" : "iterator");
        auto x = cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage);

        auto t = fmt("::hilti::rt::Set<%s>::%s", x, i);
        result = CxxTypes{.base_type = fmt("%s", t)};
    }


    void operator()(type::vector::Iterator* n) final {
        auto i = (n->dereferencedType()->isConstant() ? "const_iterator" : "iterator");
        auto x = cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n->dereferencedType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        auto t = fmt("::hilti::rt::Vector<%s%s>::%s", x, allocator, i);
        result = CxxTypes{.base_type = fmt("%s", t)};
    }

    void operator()(type::Library* n) final { result = CxxTypes{.base_type = fmt("%s", n->cxxName())}; }

    void operator()(type::List* n) final {
        std::string t;

        if ( n->elementType()->type()->isA<type::Unknown>() )
            // Can only be the empty list.
            t = "::hilti::rt::vector::Empty";
        else
            t = fmt("::hilti::rt::Vector<%s>", cg->compile(n->elementType(), codegen::TypeUsage::Storage));

        result = CxxTypes{.base_type = fmt("%s", t)};
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

        auto scope = cxx::ID{cg->unit()->cxxNamespace().namespace_()};
        auto sid = cxx::ID{scope, n->typeID()};
        auto ns = sid.namespace_();

        if ( cg->prioritizeTypes() )
            cg->unit()->prioritizeType(sid);

        result = cache->getOrCreate(
            sid, [&]() { return CxxTypes{.base_type = std::string(sid)}; },
            [&](auto& cxx_types) {
                auto render_body = cxx::Block();
                render_body.addStatement("o << ::hilti::rt::to_string(x); return o");

                auto render_decl =
                    cxx::declaration::Function{.result = "std::ostream&",
                                               .id = cxx::ID{fmt("%s::operator<<", ns)},
                                               .args = {cxx::declaration::Argument{.id = "o", .type = "std::ostream&"},
                                                        cxx::declaration::Argument{
                                                            .id = "x",
                                                            .type = fmt("const %s&", sid),
                                                        }}};

                auto render_impl = cxx::Function{.declaration = render_decl, .body = std::move(render_body)};

                cg->unit()->add(render_decl);
                cg->unit()->add(render_impl);
                cg->addDeclarationFor(type);

                return cxx_types;
            });
    }

    void operator()(type::Vector* n) final {
        std::string t;

        if ( n->elementType()->type()->isA<type::Unknown>() )
            // Can only be the empty list.
            t = "::hilti::rt::vector::Empty";
        else {
            auto x = cg->compile(n->elementType(), codegen::TypeUsage::Storage);

            std::string allocator;
            if ( auto def = cg->typeDefaultValue(n->elementType()) )
                allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

            t = fmt("::hilti::rt::Vector<%s%s>", x, allocator);
        }

        result = CxxTypes{.base_type = fmt("%s", t)};
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
            t = fmt("std::optional<%s>", cg->compile(ct, codegen::TypeUsage::Storage));
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

        result = CxxTypes{.base_type = t, .param_in = fmt("%s", t), .param_inout = fmt("%s", t)};
    }

    void operator()(type::stream::View* n) final { result = CxxTypes{.base_type = "::hilti::rt::stream::View"}; }

    void operator()(type::Result* n) final {
        std::string t;

        if ( const auto& ct = n->dereferencedType(); ! ct->isWildcard() )
            t = fmt("::hilti::rt::Result<%s>", cg->compile(ct, codegen::TypeUsage::Storage));
        else
            t = "*";

        result = CxxTypes{.base_type = t};
    }

    void operator()(type::String* n) final { result = CxxTypes{.base_type = "std::string"}; }

    void operator()(type::Struct* n) final {
        auto type_id = n->typeID();
        if ( ! type_id ) {
            // Special-case: construct a type ID for anonymous structs.
            auto ctor = n->parent(2)->tryAs<ctor::Struct>();
            auto decl = n->parent<declaration::Type>();
            if ( ctor && decl )
                type_id = decl->fullyQualifiedID() + ctor->uniqueID();
        }

        assert(type_id);

        if ( auto x = n->cxxID() ) {
            result = CxxTypes{.base_type = cxx::Type(x)};
            return;
        }

        auto scope = cxx::ID{cg->unit()->cxxNamespace().namespace_()};
        auto sid = cxx::ID{scope, type_id};
        auto ns = sid.namespace_();

        if ( cg->prioritizeTypes() )
            cg->unit()->prioritizeType(sid);

        result = cache->getOrCreate(
            sid, [&]() { return CxxTypes{.base_type = std::string(sid)}; },
            [&](auto& cxx_types) {
                auto render_body = cxx::Block();
                render_body.addStatement("o << ::hilti::rt::to_string(x); return o");

                auto render_decl =
                    cxx::declaration::Function{.result = "std::ostream&",
                                               .id = cxx::ID{fmt("%s::operator<<", ns)},
                                               .args = {cxx::declaration::Argument{.id = "o", .type = "std::ostream&"},
                                                        cxx::declaration::Argument{
                                                            .id = "x",
                                                            .type = fmt("const %s&", sid),
                                                        }}};

                auto render_impl = cxx::Function{.declaration = render_decl, .body = std::move(render_body)};

                cg->unit()->add(render_decl);
                cg->unit()->add(render_impl);
                cg->addDeclarationFor(type);

                return cxx_types;
            });
    }

    void operator()(type::Tuple* n) final {
        auto x = node::transform(n->elements(),
                                 [this](auto e) { return cg->compile(e->type(), codegen::TypeUsage::Storage); });
        auto t = fmt("std::tuple<%s>", util::join(x, ", "));
        result = CxxTypes{.base_type = t};
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
        std::string t;

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

// Visitor creaating dynamic type information instances for types that do not provide predefined static ones.
struct VisitorTypeInfoDynamic : hilti::visitor::PreOrder {
    VisitorTypeInfoDynamic(CodeGen* cg, QualifiedType* type) : cg(cg), type(type) {}

    CodeGen* cg;
    QualifiedType* type = nullptr;

    std::optional<cxx::Expression> result;

    void operator()(type::Bitfield* n) final {
        std::vector<std::string> elems;
        auto ttype = cg->compile(type, codegen::TypeUsage::Storage);

        auto i = 0;
        for ( const auto&& b : n->bits() )
            elems.push_back(fmt(
                "::hilti::rt::type_info::bitfield::Bits{ \"%s\", %s, hilti::rt::bitfield::elementOffset<%s, %d>() }",
                b->id(), cg->typeInfo(b->itemType()), ttype, i++));

        result = fmt("::hilti::rt::type_info::Bitfield(std::vector<::hilti::rt::type_info::bitfield::Bits>({%s}))",
                     util::join(elems, ", "));
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

    void operator()(type::Library* n) final { result = "::hilti::rt::type_info::Library()"; }

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
        result =
            fmt("::hilti::rt::type_info::Result(%s, ::hilti::rt::type_info::Result::accessor<%s>())",
                cg->typeInfo(n->dereferencedType()), cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage));
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

            if ( f->isStatic() || f->isNoEmit() )
                continue;

            std::string accessor;

            if ( f->isOptional() )
                accessor = fmt(", ::hilti::rt::type_info::struct_::Field::accessor_optional<%s>()",
                               cg->compile(f->type(), codegen::TypeUsage::Storage));

            cxx::ID cxx_type_id{n->typeID()};
            if ( auto x = n->cxxID() )
                cxx_type_id = x;

            fields.push_back(fmt("::hilti::rt::type_info::struct_::Field{ \"%s\", %s, offsetof(%s, %s), %s, %s%s }",
                                 cxx::ID(f->id()), cg->typeInfo(f->type()), cxx_type_id, cxx::ID(f->id()),
                                 f->isInternal(), f->isAnonymous(), accessor));
        }

        result = fmt("::hilti::rt::type_info::Struct(std::vector<::hilti::rt::type_info::struct_::Field>({%s}))",
                     util::join(fields, ", "));
    }

    void operator()(type::Tuple* n) final {
        std::vector<std::string> elems;
        auto ttype = cg->compile(type, codegen::TypeUsage::Storage);

        int i = 0;
        for ( const auto& e : n->elements() ) {
            elems.push_back(
                fmt("::hilti::rt::type_info::tuple::Element{ \"%s\", %s, hilti::rt::tuple::elementOffset<%s, %d>() }",
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

    void operator()(type::Vector* n) final {
        auto x = cg->compile(n->elementType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n->elementType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        result = fmt("::hilti::rt::type_info::Vector(%s, ::hilti::rt::type_info::Vector::accessor<%s%s>())",
                     cg->typeInfo(n->elementType()), x, allocator);
    }

    void operator()(type::vector::Iterator* n) final {
        auto x = cg->compile(n->dereferencedType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n->dereferencedType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        result =
            fmt("::hilti::rt::type_info::VectorIterator(%s, ::hilti::rt::type_info::VectorIterator::accessor<%s%s>())",
                cg->typeInfo(n->dereferencedType()), x, allocator);
    }

    void operator()(type::Name* n) final {
        assert(n->resolvedTypeIndex());
        dispatch(n->resolvedType());
    }

    void operator()(type::Auto* n) final { logger().internalError("codegen: automatic type has not been replaced"); }
};

} // anonymous namespace

cxx::Type CodeGen::compile(QualifiedType* t, codegen::TypeUsage usage) {
    auto v = VisitorStorage(this, t, &_cache_types_storage, usage);
    auto x = hilti::visitor::dispatch(v, t->type(), [](const auto& v) { return v.result; });
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
    auto x = hilti::visitor::dispatch(v, t->type(), [](const auto& v) { return v.result; });
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
    return hilti::visitor::dispatch(v, t->type(), [](const auto& v) { return v.result; });
};

const CxxTypeInfo& CodeGen::_getOrCreateTypeInfo(QualifiedType* t) {
    std::stringstream display;

    if ( t->type()->typeID() )
        // Prefer the bare type name as the display value.
        display << t->type()->typeID();
    else
        printer::print(display, t, true);

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

            if ( auto x = hilti::visitor::dispatch(v, t->type(), [](const auto& v) { return v.result; }); x && *x )
                return CxxTypeInfo{.predefined = true, .reference = fmt("&%s", *x)};

            auto forward = cxx::declaration::Constant{.id = tid,
                                                      .type = "::hilti::rt::TypeInfo",
                                                      .linkage = "extern",
                                                      .forward_decl = true};
            unit()->add(forward);
            return CxxTypeInfo{.predefined = false,
                               .reference = fmt("&%s", std::string(ID("type_info", tid.local()))),
                               .forward = forward};
        },
        [&](auto& ti) {
            if ( ti.predefined )
                return ti;

            auto v = VisitorTypeInfoDynamic(this, t);
            auto x = hilti::visitor::dispatch(v, t->type(), [](const auto& v) { return v.result; });
            if ( ! x )
                logger().internalError(fmt("codegen: type %s does not have a dynamic type info visitor", *t), t);

            auto id_init = (t->type()->typeID() ? fmt("\"%s\"", t->type()->typeID()) : std::string("{}"));
            auto init = fmt("{ %s, \"%s\", new %s }", id_init, util::escapeUTF8(display.str(), true), *x);

            ti.declaration =
                cxx::declaration::Constant{.id = tid, .type = "::hilti::rt::TypeInfo", .init = init, .linkage = ""};

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
