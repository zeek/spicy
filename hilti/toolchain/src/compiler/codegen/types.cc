// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/module.h>
#include <hilti/ast/types/all.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>
#include <hilti/compiler/unit.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::codegen;

using util::fmt;

namespace {

struct VisitorDeclaration : hilti::visitor::PreOrder<cxx::declaration::Type, VisitorDeclaration> {
    VisitorDeclaration(CodeGen* cg, util::Cache<cxx::ID, cxx::declaration::Type>* cache) : cg(cg), cache(cache) {}

    CodeGen* cg;
    util::Cache<cxx::ID, cxx::declaration::Type>* cache;
    std::list<cxx::declaration::Type> dependencies;

    void addDependency(const Type& t) {
        for ( auto&& t : cg->typeDependencies(t) )
            dependencies.push_back(std::move(t));
    }

    auto typeID(const Node& n) { return n.as<Type>().typeID(); }
    auto cxxID(const Node& n) { return n.as<Type>().cxxID(); }

    result_t operator()(const type::Struct& n, const position_t p) {
        assert(typeID(p.node));

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{*typeID(p.node)};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        return cache->getOrCreate(
            id,
            []() {
                // Just return an empty dummy for now to avoid cyclic recursion.
                return cxx::declaration::Type{};
            },
            [&](auto& dummy) {
                std::vector<cxx::declaration::Argument> args;
                std::vector<cxx::type::struct_::Member> fields;

                cxx::Block self_body;
                self_body.addStatement(util::fmt("return ::hilti::rt::ValueReference<%s>::self(this)", id));

                auto self = cxx::declaration::Function{.result = "auto",
                                                       .id = "__self",
                                                       .args = {},
                                                       .linkage = "inline",
                                                       .inline_body = std::move(self_body)};

                fields.emplace_back(std::move(self));

                cg->enablePrioritizeTypes();

                for ( const auto& p : n.parameters() ) {
                    cxx::Type type = cg->compile(p.type(), cg->parameterKindToTypeUsage(p.kind()));
                    cxx::Type internal_type = cg->compile(p.type(), codegen::TypeUsage::Storage);

                    if ( type::isReferenceType(p.type()) ) {
                        // We turn reference types into weak references for
                        // storage so that copying a struct won't cause
                        // potentially expensive copies or let us hold on to
                        // objects longer than they'd otherwise stick around.
                        assert(type::isReferenceType(p.type()));
                        internal_type = cg->compile(type::WeakReference(p.type().dereferencedType(), p.meta()),
                                                    codegen::TypeUsage::Storage);
                    }

                    std::optional<cxx::Expression> default_;
                    if ( auto x = p.default_() )
                        default_ = cg->compile(*x);
                    else
                        default_ = cg->typeDefaultValue(p.type());

                    auto arg = cxx::declaration::Argument{.id = cxx::ID(fmt("__p_%s", p.id())),
                                                          .type = type,
                                                          .default_ = std::move(default_),
                                                          .internal_type = internal_type};
                    args.emplace_back(std::move(arg));
                }

                for ( const auto& f : n.fields() ) {
                    if ( f.isNoEmit() )
                        continue;

                    if ( auto ft = f.type().tryAs<type::Function>() ) {
                        auto d = cg->compile(f.id(), *ft, declaration::Linkage::Struct,
                                             function::CallingConvention::Standard, f.attributes());

                        if ( f.isStatic() )
                            d.linkage = "static";

                        if ( auto func = f.inlineFunction(); func && func->body() ) {
                            auto cxx_body = cxx::Block();

                            if ( ! f.isStatic() ) {
                                // Need a LHS for __self.
                                auto tid = typeID(p.node);

                                if ( ! tid )
                                    logger().internalError("Struct type with hooks does not have a type ID");

                                auto id_module = tid->sub(-2);
                                auto id_class = tid->sub(-1);

                                if ( id_module.empty() )
                                    id_module = cg->hiltiUnit()->id();

                                auto id_type = cxx::ID(id_module, id_class);
                                auto self = cxx::declaration::Local{"__self", "auto", {}, fmt("%s::__self()", id_type)};
                                cxx_body.addLocal(self);
                            }

                            cg->compile(*func->body(), &cxx_body);

                            auto method_impl = cxx::Function{.declaration = d, .body = std::move(cxx_body)};
                            method_impl.declaration.id = cxx::ID(scope, sid, f.id());
                            method_impl.declaration.linkage = "inline";
                            cg->unit()->add(method_impl);
                        }

                        if ( ft->flavor() == type::function::Flavor::Hook ) {
                            auto tid = typeID(p.node);

                            if ( ! tid )
                                logger().internalError("Struct type with hooks does not have a type ID");

                            auto id_module = tid->sub(-2);
                            auto id_class = tid->sub(-1);
                            const auto& id_local = f.id();

                            if ( id_module.empty() )
                                id_module = cg->hiltiUnit()->id();

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

                            method_impl.declaration.id = cxx::ID(scope, sid, f.id());
                            method_impl.declaration.linkage = "inline";
                            cg->unit()->add(method_impl);

                            std::list<cxx::declaration::Type> aux_types = {
                                cxx::declaration::Type{cxx::ID(cg->options().cxx_namespace_intern, id_module, id_class),
                                                       fmt("struct %s", id_class),
                                                       {},
                                                       true}};

                            for ( const auto& p : ft->parameters() ) {
                                for ( auto t : cg->typeDependencies(p.type()) )
                                    aux_types.push_back(std::move(t));
                            }

                            auto hook = cxx::linker::Join{.id = cxx::ID(id_hook),
                                                          .callee = d,
                                                          .aux_types = aux_types,
                                                          .declare_only = true};

                            hook.callee.args.push_back(
                                cxx::declaration::Argument{.id = "__self",
                                                           .type = cg->compile(type::ValueReference(p.node.as<Type>()),
                                                                               codegen::TypeUsage::InOutParameter)});
                            cg->unit()->add(hook);
                        }

                        fields.emplace_back(std::move(d));
                        continue;
                    }

                    auto t = cg->compile(f.type(), codegen::TypeUsage::Storage);

                    if ( f.isOptional() )
                        t = fmt("std::optional<%s>", t);

                    std::optional<cxx::Expression> default_;
                    if ( ! f.isOptional() ) {
                        cg->pushSelf("__self()");
                        if ( auto x = f.default_() )
                            default_ = cg->compile(*x);
                        else
                            default_ = cg->typeDefaultValue(f.type());
                        cg->popSelf();
                    }

                    auto x = cxx::declaration::Local{cxx::ID(f.id()),
                                                     t,
                                                     {},
                                                     default_,
                                                     (f.isStatic() ? "inline static" : "")};

                    fields.emplace_back(std::move(x));
                }

                if ( n.hasFinalizer() ) {
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
                                           .add_ctors = true};
                return cxx::declaration::Type{id, t, t.inlineCode()};
            });

        util::cannot_be_reached();
    }

    result_t operator()(const type::Tuple& n) {
        for ( const auto& e : n.elements() )
            addDependency(e.type());

        return {};
    }

    result_t operator()(const type::Union& n, const position_t p) {
        assert(typeID(p.node));

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{*typeID(p.node)};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        // Add a forward declaration.
        auto type_forward = cxx::declaration::Type{id, fmt("struct %s", id.local()), {}, true, true};

        cg->unit()->add(type_forward);
        dependencies.push_back(type_forward);

        std::vector<cxx::type::union_::Member> fields;
        for ( const auto& f : n.fields() ) {
            auto t = cg->compile(f.type(), codegen::TypeUsage::Storage);
            auto x = cxx::declaration::Local{cxx::ID(f.id()), t};
            fields.emplace_back(std::move(x));
        }

        auto t = cxx::type::Union{.members = std::move(fields), .type_name = cxx::ID(id.local())};
        return cxx::declaration::Type{id, t};
    }

    result_t operator()(const type::Vector& n, const position_t p) {
        if ( n.elementType() != type::unknown )
            addDependency(n.elementType());

        return {};
    }

    result_t operator()(const type::Enum& n, const position_t p) {
        assert(typeID(p.node));

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{*typeID(p.node)};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        // We declare the full enum type as part of the forward declarations block, that makes sure it's always fully
        // available. This is e.g., needed so we can set default values for vectors of enums.
        auto id = cxx::ID(scope, sid);
        auto labels =
            util::transform(n.labels(), [](auto l) { return std::make_pair(cxx::ID(l.get().id()), l.get().value()); });
        auto t = cxx::type::Enum{.labels = std::move(labels), .type_name = cxx::ID(id.local())};
        auto decl = cxx::declaration::Type{id, t, {}, true, false, true};
        dependencies.push_back(decl);
        return decl;
    }

    result_t operator()(const type::Exception& n, const position_t p) {
        assert(typeID(p.node));

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{*typeID(p.node)};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        std::string base_ns = "::hilti::rt";
        std::string base_cls = "UsageError";

        if ( auto b = n.baseType() ) {
            auto x = cxx::ID(cg->compile(*b, codegen::TypeUsage::Ctor));
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

        return cxx::declaration::Type(id, fmt("HILTI_EXCEPTION_NS(%s, %s, %s)", id.local(), base_ns, base_cls), {},
                                      false, false, true);
    }
};

struct VisitorStorage : hilti::visitor::PreOrder<CxxTypes, VisitorStorage> {
    VisitorStorage(CodeGen* cg, util::Cache<cxx::ID, CxxTypes>* cache, codegen::TypeUsage usage)
        : cg(cg), cache(cache), usage(usage) {}

    CodeGen* cg;
    util::Cache<cxx::ID, CxxTypes>* cache;
    codegen::TypeUsage usage;

    auto typeID(const Node& n) { return n.as<Type>().typeID(); }
    auto cxxID(const Node& n) { return n.as<Type>().cxxID(); }

    result_t operator()(const type::Address& n) { return CxxTypes{.base_type = "::hilti::rt::Address"}; }

    result_t operator()(const type::Any& n) { return CxxTypes{.base_type = "::hilti::rt::any"}; }

    result_t operator()(const type::Bool& n) { return CxxTypes{.base_type = "::hilti::rt::Bool"}; }

    result_t operator()(const type::Bytes& n) { return CxxTypes{.base_type = "::hilti::rt::Bytes"}; }

    result_t operator()(const type::Real& n) { return CxxTypes{.base_type = "double"}; }

    result_t operator()(const type::Enum& n, position_t p) {
        assert(typeID(p.node));

        if ( auto cxx = cxxID(p.node) )
            return CxxTypes{.base_type = cxx::Type(*cxx), .default_ = cxx::Expression(cxx::ID(*cxx, "Undef"))};

        auto tid = typeID(p.node);
        assert(tid);

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{*tid};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        // Add tailored to_string() function.
        auto cases = util::transform(n.uniqueLabels(), [&](const auto& l) {
            auto b = cxx::Block();
            b.addReturn(fmt("\"%s::%s\"", tid->local(), l.get().id()));
            return std::make_pair(cxx::Expression(cxx::ID(id, l.get().id())), std::move(b));
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

        cg->addDeclarationFor(p.node.as<Type>());
        return CxxTypes{.base_type = std::string(sid), .default_ = cxx::Expression(cxx::ID(sid, "Undef"))};
    }

    result_t operator()(const type::Error& n) { return CxxTypes{.base_type = "::hilti::rt::result::Error"}; }

    result_t operator()(const type::Exception& n, const position_t p) {
        if ( auto cxx = cxxID(p.node) )
            return CxxTypes{.base_type = cxx::Type(*cxx)};

        if ( auto id = typeID(p.node) ) {
            cg->addDeclarationFor(p.node.as<Type>());
            return CxxTypes{.base_type = std::string(*id), .storage = "::hilti::rt::Exception"};
        }
        else
            return CxxTypes{.base_type = "::hilti::rt::Exception"};
    }

    result_t operator()(const type::Function& n) { return CxxTypes{}; }

    result_t operator()(const type::Interval& n) { return CxxTypes{.base_type = "::hilti::rt::Interval"}; }

    result_t operator()(const type::bytes::Iterator& n) {
        return CxxTypes{.base_type = "::hilti::rt::bytes::Iterator"};
    }

    result_t operator()(const type::stream::Iterator& n) {
        return CxxTypes{.base_type = "::hilti::rt::stream::SafeConstIterator"};
    }

    result_t operator()(const type::list::Iterator& n) {
        auto t =
            fmt("::hilti::rt::Vector<%s>::iterator_t", cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage));
        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::map::Iterator& n) {
        auto i = (n.isConstant() ? "const_iterator" : "iterator");
        auto k = cg->compile(n.keyType(), codegen::TypeUsage::Storage);
        auto v = cg->compile(n.valueType(), codegen::TypeUsage::Storage);

        auto t = fmt("::hilti::rt::Map<%s, %s>::%s", k, v, i);
        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::set::Iterator& n) {
        auto i = (n.isConstant() ? "const_iterator" : "iterator");
        auto x = cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage);

        auto t = fmt("::hilti::rt::Set<%s>::%s", x, i);
        return CxxTypes{.base_type = fmt("%s", t)};
    }


    result_t operator()(const type::vector::Iterator& n) {
        auto i = (n.isConstant() ? "const_iterator" : "iterator");
        auto x = cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n.dereferencedType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        auto t = fmt("::hilti::rt::Vector<%s%s>::%s", x, allocator, i);
        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Library& n) { return CxxTypes{.base_type = fmt("%s", n.cxxName())}; }

    result_t operator()(const type::List& n) {
        std::string t;

        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            t = "::hilti::rt::vector::Empty";
        else
            t = fmt("::hilti::rt::Vector<%s>", cg->compile(n.elementType(), codegen::TypeUsage::Storage));

        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Map& n) {
        std::string t;

        if ( n.elementType() == type::unknown )
            // Can only be the empty map.
            t = "::hilti::rt::map::Empty";
        else {
            auto k = cg->compile(n.keyType(), codegen::TypeUsage::Storage);
            auto v = cg->compile(n.elementType(), codegen::TypeUsage::Storage);
            t = fmt("::hilti::rt::Map<%s, %s>", k, v);
        }

        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Network& n) { return CxxTypes{.base_type = "::hilti::rt::Network"}; }

    result_t operator()(const type::Null& n) { return CxxTypes{.base_type = "::hilti::rt::Null"}; }

    result_t operator()(const type::Port& n) { return CxxTypes{.base_type = "::hilti::rt::Port"}; }

    result_t operator()(const type::RegExp& n) { return CxxTypes{.base_type = "::hilti::rt::RegExp"}; }

    result_t operator()(const type::SignedInteger& n) {
        cxx::Type t;

        switch ( n.width() ) {
            case 8: t = "::hilti::rt::integer::safe<int8_t>"; break;
            case 16: t = "::hilti::rt::integer::safe<int16_t>"; break;
            case 32: t = "::hilti::rt::integer::safe<int32_t>"; break;
            case 64: t = "::hilti::rt::integer::safe<int64_t>"; break;
            default: logger().internalError("codegen: unexpected integer width", n);
        }

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::Set& n) {
        std::string t;

        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            t = "::hilti::rt::set::Empty";
        else {
            auto x = cg->compile(n.elementType(), codegen::TypeUsage::Storage);
            t = fmt("::hilti::rt::Set<%s>", x);
        }

        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Stream& n) { return CxxTypes{.base_type = "::hilti::rt::Stream"}; }

    result_t operator()(const type::Union& n, position_t p) {
        assert(typeID(p.node));

        if ( auto x = cxxID(p.node) )
            return CxxTypes{.base_type = cxx::Type(*x)};

        auto scope = cxx::ID{cg->unit()->cxxNamespace().namespace_()};
        auto sid = cxx::ID{scope, *typeID(p.node)};
        auto ns = sid.namespace_();

        if ( cg->prioritizeTypes() )
            cg->unit()->prioritizeType(sid);

        return cache->getOrCreate(
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
                cg->addDeclarationFor(p.node.as<Type>());

                return cxx_types;
            });
    }

    result_t operator()(const type::Vector& n) {
        std::string t;

        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            t = "::hilti::rt::vector::Empty";
        else {
            auto x = cg->compile(n.elementType(), codegen::TypeUsage::Storage);

            std::string allocator;
            if ( auto def = cg->typeDefaultValue(n.elementType()) )
                allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

            t = fmt("::hilti::rt::Vector<%s%s>", x, allocator);
        }

        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Time& n) { return CxxTypes{.base_type = "::hilti::rt::Time"}; }

    result_t operator()(const type::UnsignedInteger& n) {
        cxx::Type t;

        switch ( n.width() ) {
            case 8:
                t = "::hilti::rt::integer::safe<uint8_t>";
                break; // 2 bytes to avoid overloading confusion with uchar_t
            case 16: t = "::hilti::rt::integer::safe<uint16_t>"; break;
            case 32: t = "::hilti::rt::integer::safe<uint32_t>"; break;
            case 64: t = "::hilti::rt::integer::safe<uint64_t>"; break;
            default: logger().internalError("codegen: unexpected integer width", n);
        }

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::Optional& n) {
        std::string t;

        if ( const auto& ct = n.dereferencedType(); ! ct.isWildcard() )
            t = fmt("std::optional<%s>", cg->compile(ct, codegen::TypeUsage::Storage));
        else
            t = "*";

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::StrongReference& n) {
        std::string t;

        if ( const auto& ct = n.dereferencedType(); ! ct.isWildcard() )
            t = fmt("::hilti::rt::StrongReference<%s>", cg->compile(ct, codegen::TypeUsage::Ctor)); // XXX
        else
            t = "*";

        return CxxTypes{.base_type = t, .param_in = fmt("%s", t), .param_inout = fmt("%s", t)};
    }

    result_t operator()(const type::stream::View& n) { return CxxTypes{.base_type = "::hilti::rt::stream::View"}; }

    result_t operator()(const type::Result& n) {
        std::string t;

        if ( const auto& ct = n.dereferencedType(); ! ct.isWildcard() )
            t = fmt("::hilti::rt::Result<%s>", cg->compile(ct, codegen::TypeUsage::Storage));
        else
            t = "*";

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::String& n) { return CxxTypes{.base_type = "std::string"}; }

    result_t operator()(const type::Struct& n, position_t p) {
        assert(typeID(p.node));

        if ( auto x = cxxID(p.node) )
            return CxxTypes{.base_type = cxx::Type(*x)};

        auto scope = cxx::ID{cg->unit()->cxxNamespace().namespace_()};
        auto sid = cxx::ID{scope, *typeID(p.node)};
        auto ns = sid.namespace_();

        if ( cg->prioritizeTypes() )
            cg->unit()->prioritizeType(sid);

        return cache->getOrCreate(
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
                cg->addDeclarationFor(p.node.as<Type>());

                return cxx_types;
            });
    }

    result_t operator()(const type::Tuple& n) {
        auto x = node::transform(n.elements(),
                                 [this](auto e) { return cg->compile(e.type(), codegen::TypeUsage::Storage); });
        auto t = fmt("std::tuple<%s>", util::join(x, ", "));
        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::UnresolvedID& n) {
        logger().internalError(fmt("codegen: unresolved type ID %s", n.id()), n);
    }

    result_t operator()(const type::Void& n) { return CxxTypes{.base_type = "void"}; }

    result_t operator()(const type::Auto& n) {
        logger().internalError("codegen: automatic type has not been replaced");
    }

    result_t operator()(const type::WeakReference& n) {
        std::string t;

        if ( const auto& ct = n.dereferencedType(); ! ct.isWildcard() )
            t = fmt("::hilti::rt::WeakReference<%s>", cg->compile(ct, codegen::TypeUsage::Ctor));
        else
            t = "*";

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::ValueReference& n) {
        std::string t;

        if ( const auto& ct = n.dereferencedType(); ! ct.isWildcard() ) {
            auto element_type = cg->compile(ct, codegen::TypeUsage::Ctor);
            return CxxTypes{.base_type = fmt("::hilti::rt::ValueReference<%s>", element_type), .ctor = element_type};
        }
        else
            return CxxTypes{.base_type = "*"};
    }
};

// Visitor returning the ID of static, predefined type information instances for types that provide it.
struct VisitorTypeInfoPredefined : hilti::visitor::PreOrder<cxx::Expression, VisitorTypeInfoPredefined> {
    VisitorTypeInfoPredefined(CodeGen* cg) : cg(cg) {}

    CodeGen* cg;

    result_t operator()(const type::Address& n) { return "::hilti::rt::type_info::address"; }
    result_t operator()(const type::Any& n) { return "::hilti::rt::type_info::any"; }
    result_t operator()(const type::Bool& n) { return "::hilti::rt::type_info::bool_"; }
    result_t operator()(const type::Bytes& n) { return "::hilti::rt::type_info::bytes"; }
    result_t operator()(const type::bytes::Iterator& n) { return "::hilti::rt::type_info::bytes_iterator"; }
    result_t operator()(const type::Error& n) { return "::hilti::rt::type_info::error"; }
    result_t operator()(const type::Interval& n) { return "::hilti::rt::type_info::interval"; }
    result_t operator()(const type::Network& n) { return "::hilti::rt::type_info::network"; }
    result_t operator()(const type::Port& n) { return "::hilti::rt::type_info::port"; }
    result_t operator()(const type::Real& n) { return "::hilti::rt::type_info::real"; }
    result_t operator()(const type::RegExp& n) { return "::hilti::rt::type_info::regexp"; }
    result_t operator()(const type::SignedInteger& n) { return fmt("::hilti::rt::type_info::int%d", n.width()); }
    result_t operator()(const type::Stream& n) { return "::hilti::rt::type_info::stream"; }
    result_t operator()(const type::stream::Iterator& n) { return "::hilti::rt::type_info::stream_iterator"; }
    result_t operator()(const type::stream::View& n) { return "::hilti::rt::type_info::stream_view"; }
    result_t operator()(const type::String& n) { return "::hilti::rt::type_info::string"; }
    result_t operator()(const type::Time& n) { return "::hilti::rt::type_info::time"; }
    result_t operator()(const type::UnsignedInteger& n) { return fmt("::hilti::rt::type_info::uint%d", n.width()); }
    result_t operator()(const type::Void& n) { return "::hilti::rt::type_info::void_"; }

    result_t operator()(const type::UnresolvedID& n) {
        logger().internalError(fmt("codegen: unresolved type ID %s", n.id()), n);
    }

    result_t operator()(const type::Auto& n) {
        logger().internalError("codegen: automatic type has not been replaced");
    }
};

// Visitor creaating dynamic type information instances for types that do not provide predefined static ones.
struct VisitorTypeInfoDynamic : hilti::visitor::PreOrder<cxx::Expression, VisitorTypeInfoDynamic> {
    VisitorTypeInfoDynamic(CodeGen* cg) : cg(cg) {}
    CodeGen* cg;

    auto typeID(const Node& n) { return n.as<Type>().typeID(); }
    auto cxxID(const Node& n) { return n.as<Type>().cxxID(); }

    result_t operator()(const type::Enum& n) {
        std::vector<std::string> labels;

        for ( const auto& l : n.labels() )
            labels.push_back(
                fmt("::hilti::rt::type_info::enum_::Label{ \"%s\", %d }", cxx::ID(l.get().id()), l.get().value()));

        return fmt("::hilti::rt::type_info::Enum(std::vector<::hilti::rt::type_info::enum_::Label>({%s}))",
                   util::join(labels, ", "));
    }

    result_t operator()(const type::Exception& n, position_t p) { return "::hilti::rt::type_info::Exception()"; }

    result_t operator()(const type::Function& n) { return "::hilti::rt::type_info::Function()"; }

    result_t operator()(const type::Library& n) { return "::hilti::rt::type_info::Library()"; }

    result_t operator()(const type::Map& n) {
        auto ktype = cg->compile(n.keyType(), codegen::TypeUsage::Storage);
        auto vtype = cg->compile(n.elementType(), codegen::TypeUsage::Storage);
        auto deref_type = type::Tuple({n.keyType(), n.elementType()});
        return fmt("::hilti::rt::type_info::Map(%s, %s, ::hilti::rt::type_info::Map::accessor<%s, %s>())",
                   cg->typeInfo(n.keyType()), cg->typeInfo(n.elementType()),
                   cg->compile(n.keyType(), codegen::TypeUsage::Storage),
                   cg->compile(n.elementType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::map::Iterator& n) {
        return fmt(
            "::hilti::rt::type_info::MapIterator(%s, %s, ::hilti::rt::type_info::MapIterator::accessor<%s, %s>())",
            cg->typeInfo(n.keyType()), cg->typeInfo(n.valueType()),
            cg->compile(n.keyType(), codegen::TypeUsage::Storage),
            cg->compile(n.valueType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::Optional& n) {
        return fmt("::hilti::rt::type_info::Optional(%s, ::hilti::rt::type_info::Optional::accessor<%s>())",
                   cg->typeInfo(n.dereferencedType()), cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::Result& n) {
        return fmt("::hilti::rt::type_info::Result(%s, ::hilti::rt::type_info::Result::accessor<%s>())",
                   cg->typeInfo(n.dereferencedType()), cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::Set& n) {
        return fmt("::hilti::rt::type_info::Set(%s, ::hilti::rt::type_info::Set::accessor<%s>())",
                   cg->typeInfo(n.elementType()), cg->compile(n.elementType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::set::Iterator& n) {
        return fmt("::hilti::rt::type_info::SetIterator(%s, ::hilti::rt::type_info::SetIterator::accessor<%s>())",
                   cg->typeInfo(n.dereferencedType()), cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::Struct& n, position_t p) {
        std::vector<std::string> fields;

        for ( const auto& f : n.fields() ) {
            if ( auto ft = f.type().tryAs<type::Function>() )
                continue;

            if ( f.isStatic() || f.isNoEmit() )
                continue;

            std::string accessor;

            if ( f.isOptional() )
                accessor = fmt(", ::hilti::rt::type_info::struct_::Field::accessor_optional<%s>()",
                               cg->compile(f.type(), codegen::TypeUsage::Storage));

            cxx::ID cxx_type_id{*typeID(p.node)};
            if ( auto x = cxxID(p.node) )
                cxx_type_id = *x;

            fields.push_back(fmt("::hilti::rt::type_info::struct_::Field{ \"%s\", %s, offsetof(%s, %s), %s%s }",
                                 cxx::ID(f.id()), cg->typeInfo(f.type()), cxx_type_id, cxx::ID(f.id()), f.isInternal(),
                                 accessor));
        }

        return fmt("::hilti::rt::type_info::Struct(std::vector<::hilti::rt::type_info::struct_::Field>({%s}))",
                   util::join(fields, ", "));
    }

    result_t operator()(const type::Tuple& n, position_t p) {
        std::vector<std::string> elems;
        auto ttype = cg->compile(p.node.as<Type>(), codegen::TypeUsage::Storage);

        for ( const auto&& [i, e] : util::enumerate(n.elements()) )
            elems.push_back(
                fmt("::hilti::rt::type_info::tuple::Element{ \"%s\", %s, hilti::rt::tuple::elementOffset<%s, %d>() }",
                    e.id() ? *e.id() : ID(), cg->typeInfo(e.type()), ttype, i));

        return fmt("::hilti::rt::type_info::Tuple(std::vector<::hilti::rt::type_info::tuple::Element>({%s}))",
                   util::join(elems, ", "));
    }

    result_t operator()(const type::Union& n, position_t p) {
        std::vector<std::string> fields;

        for ( const auto& f : n.fields() )
            fields.push_back(
                fmt("::hilti::rt::type_info::union_::Field{ \"%s\", %s }", cxx::ID(f.id()), cg->typeInfo(f.type())));

        return fmt(
            "::hilti::rt::type_info::Union(std::vector<::hilti::rt::type_info::union_::Field>({%s}), "
            "::hilti::rt::type_info::Union::accessor<%s>())",
            util::join(fields, ", "), cg->compile(p.node.as<Type>(), codegen::TypeUsage::Storage));
    }
    result_t operator()(const type::StrongReference& n) {
        return fmt(
            "::hilti::rt::type_info::StrongReference(%s, ::hilti::rt::type_info::StrongReference::accessor<%s>())",
            cg->typeInfo(n.dereferencedType()), cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::ValueReference& n) {
        return fmt("::hilti::rt::type_info::ValueReference(%s, ::hilti::rt::type_info::ValueReference::accessor<%s>())",
                   cg->typeInfo(n.dereferencedType()), cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::WeakReference& n) {
        return fmt("::hilti::rt::type_info::WeakReference(%s, ::hilti::rt::type_info::WeakReference::accessor<%s>())",
                   cg->typeInfo(n.dereferencedType()), cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage));
    }

    result_t operator()(const type::Vector& n) {
        auto x = cg->compile(n.elementType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n.elementType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        return fmt("::hilti::rt::type_info::Vector(%s, ::hilti::rt::type_info::Vector::accessor<%s%s>())",
                   cg->typeInfo(n.elementType()), x, allocator);
    }

    result_t operator()(const type::vector::Iterator& n) {
        auto x = cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n.dereferencedType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        return fmt(
            "::hilti::rt::type_info::VectorIterator(%s, ::hilti::rt::type_info::VectorIterator::accessor<%s%s>())",
            cg->typeInfo(n.dereferencedType()), x, allocator);
    }

    result_t operator()(const type::Auto& n) {
        logger().internalError("codegen: automatic type has not been replaced");
    }

    result_t operator()(const type::UnresolvedID& n) {
        logger().internalError(fmt("codegen: unresolved type ID %s", n.id()), n);
    }
};

} // anonymous namespace

cxx::Type CodeGen::compile(const hilti::Type& t, codegen::TypeUsage usage) {
    auto x = VisitorStorage(this, &_cache_types_storage, usage).dispatch(t);

    if ( ! x ) {
        hilti::render(std::cerr, t);
        logger().internalError(fmt("codegen: type %s does not have a visitor", t), t);
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

            logger().internalError(fmt("codegen: type %s does not support use as storage", to_node(t).render()), t);
            break;

        case codegen::TypeUsage::CopyParameter:
            if ( x->param_copy )
                return std::move(*x->param_copy);

            if ( base_type )
                return fmt("%s", *base_type);

            logger().internalError(fmt("codegen: type %s does not support use as copy-parameter ", to_node(t).render()),
                                   t);
            break;

        case codegen::TypeUsage::InParameter:
            if ( x->param_in )
                return std::move(*x->param_in);

            if ( base_type )
                return fmt("const %s&", *base_type);

            logger().internalError(fmt("codegen: type %s does not support use as in-parameter ", to_node(t).render()),
                                   t);
            break;

        case codegen::TypeUsage::InOutParameter:
            if ( x->param_inout )
                return std::move(*x->param_inout);

            if ( base_type )
                return fmt("%s&", *base_type);

            logger().internalError(fmt("codegen: type %s does not support use as inout-parameter ",
                                       to_node(t).render()),
                                   t);
            break;

        case codegen::TypeUsage::FunctionResult:
            if ( x->result )
                return std::move(*x->result);

            if ( base_type )
                return std::move(*base_type);

            logger().internalError(fmt("codegen: type %s does not support use as function result", to_node(t).render()),
                                   t);
            break;

        case codegen::TypeUsage::Ctor:
            if ( x->ctor )
                return std::move(*x->ctor);

            if ( x->base_type )
                return std::move(*x->base_type);

            logger().internalError(fmt("codegen: type %s does not support use as storage", to_node(t).render()), t);
            break;

        case codegen::TypeUsage::None:
            logger().internalError(fmt("codegen: type compilation with 'None' usage", to_node(t).render()), t);
            break;
        default: util::cannot_be_reached();
    }
}

std::optional<cxx::Expression> CodeGen::typeDefaultValue(const hilti::Type& t) {
    auto x = VisitorStorage(this, &_cache_types_storage, codegen::TypeUsage::None).dispatch(t);

    if ( ! x ) {
        hilti::render(std::cerr, t);
        logger().internalError(fmt("codegen: type %s does not have a visitor", t), t);
    }


    return std::move(x->default_);
};

std::list<cxx::declaration::Type> CodeGen::typeDependencies(const hilti::Type& t) {
    VisitorDeclaration v(this, &_cache_types_declarations);
    v.dispatch(t);
    return v.dependencies;
};

std::optional<cxx::declaration::Type> CodeGen::typeDeclaration(const hilti::Type& t) {
    return VisitorDeclaration(this, &_cache_types_declarations).dispatch(t);
};

const CxxTypeInfo& CodeGen::_getOrCreateTypeInfo(const hilti::Type& t) {
    std::stringstream display;

    if ( t.typeID() )
        // Prefer the bare type name as the display value.
        display << *t.typeID();
    else
        hilti::print(display, t);

    if ( display.str().empty() )
        logger().internalError(fmt("codegen: type %s does not have a display rendering for type information",
                                   t.typename_()),
                               t);

    // Each module contains all the type information it needs. We put the
    // declarations into an anonymous namespace so that they won't be
    // externally visible.
    cxx::ID tid(options().cxx_namespace_intern, "type_info", "", fmt("__ti_%s", util::toIdentifier(display.str())));

    return _cache_type_info.getOrCreate(
        tid,
        [&]() {
            if ( auto x = VisitorTypeInfoPredefined(this).dispatch(t); x && *x )
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

            auto x = VisitorTypeInfoDynamic(this).dispatch(t);

            if ( ! x )
                logger().internalError(fmt("codegen: type %s does not have a dynamic type info visitor", t), t);

            auto id_init = (t.typeID() ? fmt("\"%s\"", *t.typeID()) : std::string("{}"));
            auto init = fmt("{ %s, \"%s\", new %s }", id_init, display.str(), *x);

            ti.declaration =
                cxx::declaration::Constant{.id = tid, .type = "::hilti::rt::TypeInfo", .init = init, .linkage = ""};

            unit()->add(*ti.declaration);

            return ti;
        });
}

cxx::Expression CodeGen::_makeLhs(cxx::Expression expr, const Type& type) {
    if ( expr.isLhs() )
        return expr;

    auto tmp = addTmp("lhs", compile(type, TypeUsage::Storage));
    cxx::Expression result;

    if ( type.isA<type::ValueReference>() )
        result = cxx::Expression{fmt("(%s=(%s).asSharedPtr())", tmp, expr), cxx::Side::LHS}; // avoid copy
    else
        result = cxx::Expression{fmt("(%s=(%s))", tmp, expr), cxx::Side::LHS};

    // This can help show where LHS conversions happen unexpectedly; they
    // should be very rare.
    HILTI_DEBUG(logging::debug::CodeGen, fmt("RHS -> LHS: %s -> %s [%s]", expr, result, type.typename_()));

    return result;
}

cxx::Expression CodeGen::typeInfo(const hilti::Type& t) { return _getOrCreateTypeInfo(t).reference; };

void CodeGen::addTypeInfoDefinition(const hilti::Type& t) { _getOrCreateTypeInfo(t); }
