// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/module.h>
#include <hilti/ast/types/all.h>
#include <hilti/base/logger.h>
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

    result_t operator()(const type::Struct& n, const position_t p) {
        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{(n.typeID() ? std::string(*n.typeID()) : fmt("struct_%p", &n))};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        return cache->getOrCreate(
            id,
            []() {
                // Just return an empty dummy for now to avoid cyclic recursion.
                return cxx::declaration::Type{.id = "", .type = ""};
            },
            [&](auto& dummy) {
                std::vector<cxx::declaration::Argument> args;
                std::vector<cxx::type::struct_::Member> fields;

                cg->enablePrioritizeTypes();

                cxx::Type type;
                cxx::Type internal_type;

                for ( const auto& p : n.parameters() ) {
                    type = cg->compile(p.type(), codegen::TypeUsage::InParameter);
                    internal_type = cg->compile(p.type(), codegen::TypeUsage::Storage);

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

                        if ( ft->flavor() == type::function::Flavor::Hook ) {
                            auto tid = n.typeID();

                            if ( ! tid )
                                logger().internalError("Struct type with hooks does not have a type ID");

                            auto id_module = tid->sub(-2);
                            auto id_class = tid->sub(-1);
                            auto id_local = f.id();

                            if ( id_module.empty() )
                                id_module = cg->hiltiUnit()->id();

                            auto id_hook = cxx::ID(cg->options().cxx_namespace_intern, id_module,
                                                   fmt("__hook_%s_%s", id_class, id_local));
                            auto id_type = cxx::ID(id_module, id_class);

                            auto args = util::transform(d.args, [](auto& a) { return a.id; });
                            args.emplace_back("__self");

                            auto method_body = cxx::Block();
                            auto self = cxx::declaration::Local{.id = "__self",
                                                                .type = "auto",
                                                                .init = fmt("hilti::rt::ValueReference<%s>::self(this)",
                                                                            id_type)};
                            method_body.addLocal(self);
                            method_body.addStatement(fmt("return %s(%s)", id_hook, util::join(args, ", ")));

                            auto method_impl = cxx::Function{.declaration = d, .body = std::move(method_body)};

                            method_impl.declaration.id = cxx::ID(scope, sid, f.id());
                            method_impl.declaration.linkage = "inline";
                            cg->unit()->add(method_impl);

                            std::list<cxx::declaration::Type> aux_types = {
                                cxx::declaration::Type{.id = cxx::ID(cg->options().cxx_namespace_intern, id_module,
                                                                     id_class),
                                                       .type = fmt("struct %s", id_class),
                                                       .forward_decl = true}};

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
                                                           .type = cg->compile(type::ValueReference(n),
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
                        if ( auto x = f.default_() )
                            default_ = cg->compile(*x);
                        else
                            default_ = cg->typeDefaultValue(f.type());
                    }

                    auto x = cxx::declaration::Local{.id = cxx::ID(f.id()),
                                                     .type = t,
                                                     .init = default_,
                                                     .linkage = (f.isStatic() ? "inline static" : "")};

                    fields.emplace_back(std::move(x));
                }

                cg->disablePrioritizeTypes();

                // Also add a forward declaration.
                auto type_forward = cxx::declaration::Type{
                    .id = id,
                    .type = fmt("struct %s", id),
                    .forward_decl = true,
                    .forward_decl_prio = true,
                };

                cg->unit()->add(type_forward);
                dependencies.push_back(type_forward);

                auto t = cxx::type::Struct{.args = std::move(args),
                                           .members = std::move(fields),
                                           .type_name = cxx::ID(id.local()),
                                           .add_ctors = true};
                return cxx::declaration::Type{.id = id, .type = t, .inline_code = t.inlineCode()};
            });

        util::cannot_be_reached();
    }

    result_t operator()(const type::Tuple& n) {
        for ( const auto& t : n.types() )
            addDependency(t);

        return {};
    }

    result_t operator()(const type::Union& n, const position_t p) {
        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{(n.typeID() ? std::string(*n.typeID()) : fmt("union_%p", &n))};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        // Add a forward declaration.
        auto type_forward = cxx::declaration::Type{
            .id = id,
            .type = fmt("struct %s", id.local()),
            .forward_decl = true,
            .forward_decl_prio = true,
        };

        cg->unit()->add(type_forward);
        dependencies.push_back(type_forward);

        std::vector<cxx::type::union_::Member> fields;
        for ( const auto& f : n.fields() ) {
            auto t = cg->compile(f.type(), codegen::TypeUsage::Storage);
            auto x = cxx::declaration::Local{.id = cxx::ID(f.id()), .type = t};
            fields.emplace_back(std::move(x));
        }

        auto t = cxx::type::Union{.members = std::move(fields), .type_name = cxx::ID(id.local())};
        return cxx::declaration::Type{.id = id, .type = t};
    }

    result_t operator()(const type::Enum& n, const position_t p) {
        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{(n.typeID() ? std::string(*n.typeID()) : fmt("enum_%p", &n))};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        // Also add a forward declaration.
        auto type_forward = cxx::declaration::Type{
            .id = id,
            .type = fmt("enum class %s : int64_t", id.local()),
            .forward_decl = true,
            .forward_decl_prio = true,
        };

        cg->unit()->add(type_forward);
        dependencies.push_back(type_forward);

        auto labels = util::transform(n.labels(), [](auto l) { return std::make_pair(cxx::ID(l.id()), l.value()); });
        auto t = cxx::type::Enum{.labels = std::move(labels), .type_name = cxx::ID(id.local())};
        return cxx::declaration::Type{.id = id, .type = t};
    }

    result_t operator()(const type::Exception& n, const position_t p) {
        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{(n.typeID() ? std::string(*n.typeID()) : fmt("exception_%p", &n))};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        std::string base_ns = "hilti::rt";
        std::string base_cls = "UserException";

        if ( auto b = n.baseType() ) {
            auto x = cxx::ID(cg->compile(*b, codegen::TypeUsage::Ctor));
            base_ns = x.namespace_();
            base_cls = x.local();
        }

        auto id = cxx::ID(scope, sid);
        return cxx::declaration::Type{.id = id,
                                      .type = fmt("HILTI_EXCEPTION_NS(%s, %s, %s)", id.local(), base_ns, base_cls),
                                      .no_using = true};
    }
};

struct VisitorStorage : hilti::visitor::PreOrder<CxxTypes, VisitorStorage> {
    VisitorStorage(CodeGen* cg, util::Cache<cxx::ID, CxxTypes>* cache, codegen::TypeUsage usage)
        : cg(cg), cache(cache), usage(usage) {}

    CodeGen* cg;
    util::Cache<cxx::ID, CxxTypes>* cache;
    codegen::TypeUsage usage;

    result_t operator()(const type::Address& n) { return CxxTypes{.base_type = "hilti::rt::Address"}; }

    result_t operator()(const type::Any& n) { return CxxTypes{.base_type = "std::any"}; }

    result_t operator()(const type::Bool& n) { return CxxTypes{.base_type = "bool"}; }

    result_t operator()(const type::Bytes& n) { return CxxTypes{.base_type = "hilti::rt::Bytes"}; }

    result_t operator()(const type::Real& n) { return CxxTypes{.base_type = "double"}; }

    result_t operator()(const type::Enum& n, const position_t p) {
        if ( auto cxx = n.cxxID() )
            return CxxTypes{.base_type = cxx::Type(*cxx), .default_ = cxx::Expression(cxx::ID(*cxx, "Undef"))};

        auto scope = cxx::ID{cg->unit()->cxxNamespace()};
        auto sid = cxx::ID{(n.typeID() ? std::string(*n.typeID()) : fmt("enum_%p", &n))};

        if ( sid.namespace_() )
            scope = scope.namespace_();

        auto id = cxx::ID(scope, sid);

        // Add tailored to_string() function.
        auto cases = util::transform(n.uniqueLabels(), [&](auto l) {
            auto b = cxx::Block();
            b.addReturn(fmt("\"%s\"", cxx::ID(id.local(), l.id())));
            return std::make_pair(cxx::Expression(cxx::ID(id, l.id())), std::move(b));
        });

        auto default_ = cxx::Block();
        default_.addReturn(
            fmt(R"(hilti::rt::fmt("%s::<unknown-%%" PRIu64 ">", static_cast<uint64_t>(x)))", id.local()));

        auto body = cxx::Block();
        body.addSwitch("x", cases, std::move(default_));

        auto ts_decl = cxx::declaration::Function{.result = "std::string",
                                                  .id = {"hilti::rt::detail::adl", "to_string"},
                                                  .args = {cxx::declaration::Argument{.id = "x", .type = cxx::Type(id)},
                                                           cxx::declaration::Argument{.id = "", .type = "adl::tag"}},
                                                  .linkage = "inline"};

        auto ts_impl = cxx::Function{.declaration = ts_decl, .body = std::move(body)};

        cg->unit()->add(ts_decl);
        cg->unit()->add(ts_impl);

        // Add tailored operator<<.
        auto render_body = cxx::Block();
        render_body.addStatement("o << hilti::rt::to_string(x); return o");

        auto render_decl =
            cxx::declaration::Function{.result = "std::ostream&",
                                       .id = cxx::ID{fmt("%s::operator<<", id.namespace_())},
                                       .args = {cxx::declaration::Argument{.id = "o", .type = "std::ostream&"},
                                                cxx::declaration::Argument{.id = "x", .type = cxx::Type(id.local())}}};

        auto render_impl = cxx::Function{.declaration = render_decl, .body = std::move(render_body)};

        cg->unit()->add(render_decl);
        cg->unit()->add(render_impl);

        cg->addDeclarationFor(n);
        return CxxTypes{.base_type = std::string(sid), .default_ = cxx::Expression(cxx::ID(sid, "Undef"))};
    }

    result_t operator()(const type::Error& n) { return CxxTypes{.base_type = "hilti::rt::result::Error"}; }

    result_t operator()(const type::Exception& n, const position_t p) {
        if ( auto cxx = n.cxxID() )
            return CxxTypes{.base_type = cxx::Type(*cxx), .default_ = cxx::Expression(cxx::ID(*cxx, "Undef"))};

        cg->addDeclarationFor(n);

        auto sid = cxx::ID{(n.typeID() ? std::string(*n.typeID()) : fmt("exception_%p", &n))};
        return CxxTypes{.base_type = std::string(sid), .default_ = cxx::Expression(cxx::ID(sid, "Undef"))};
    }

    result_t operator()(const type::Function& n) { return CxxTypes{}; }

    result_t operator()(const type::Interval& n) { return CxxTypes{.base_type = "hilti::rt::Interval"}; }

    result_t operator()(const type::bytes::Iterator& n) { return CxxTypes{.base_type = "hilti::rt::bytes::Iterator"}; }

    result_t operator()(const type::stream::Iterator& n) {
        return CxxTypes{.base_type = "hilti::rt::stream::SafeConstIterator"};
    }

    result_t operator()(const type::list::Iterator& n) {
        auto t = fmt("hilti::rt::List<%s>::iterator_t", cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage));
        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::map::Iterator& n) {
        auto i = (n.isConstant() ? "const_iterator" : "iterator");
        auto k = cg->compile(n.containerType().as<type::Map>().keyType(), codegen::TypeUsage::Storage);
        auto v = cg->compile(n.containerType().as<type::Map>().elementType(), codegen::TypeUsage::Storage);

        auto t = fmt("hilti::rt::Map<%s, %s>::%s", k, v, i);
        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::set::Iterator& n) {
        auto i = (n.isConstant() ? "const_iterator" : "iterator");
        auto x = cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage);

        auto t = fmt("hilti::rt::Set<%s>::%s", x, i);
        return CxxTypes{.base_type = fmt("%s", t)};
    }


    result_t operator()(const type::vector::Iterator& n) {
        auto i = (n.isConstant() ? "const_iterator" : "iterator");
        auto x = cg->compile(n.dereferencedType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n.dereferencedType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        auto t = fmt("hilti::rt::Vector<%s%s>::%s", x, allocator, i);
        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Library& n) { return CxxTypes{.base_type = fmt("%s", n.cxxName())}; }

    result_t operator()(const type::List& n) {
        std::string t;

        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            t = "hilti::rt::list::Empty";
        else
            t = fmt("hilti::rt::List<%s>", cg->compile(n.elementType(), codegen::TypeUsage::Storage));

        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Map& n) {
        std::string t;

        if ( n.elementType() == type::unknown )
            // Can only be the empty map.
            t = "hilti::rt::map::Empty";
        else {
            auto k = cg->compile(n.keyType(), codegen::TypeUsage::Storage);
            auto v = cg->compile(n.elementType(), codegen::TypeUsage::Storage);
            t = fmt("hilti::rt::Map<%s, %s>", k, v);
        }

        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Network& n) { return CxxTypes{.base_type = "hilti::rt::Network"}; }

    result_t operator()(const type::Null& n) { return CxxTypes{.base_type = "hilti::rt::Null"}; }

    result_t operator()(const type::Port& n) { return CxxTypes{.base_type = "hilti::rt::Port"}; }

    result_t operator()(const type::RegExp& n) { return CxxTypes{.base_type = "hilti::rt::RegExp"}; }

    result_t operator()(const type::SignedInteger& n) {
        cxx::Type t;

        switch ( n.width() ) {
            case 8: t = "hilti::rt::integer::safe<int8_t>"; break;
            case 16: t = "hilti::rt::integer::safe<int16_t>"; break;
            case 32: t = "hilti::rt::integer::safe<int32_t>"; break;
            case 64: t = "hilti::rt::integer::safe<int64_t>"; break;
            default: logger().internalError("codegen: unexpected integer width", n);
        }

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::Set& n) {
        std::string t;

        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            t = "hilti::rt::set::Empty";
        else {
            auto x = cg->compile(n.elementType(), codegen::TypeUsage::Storage);
            t = fmt("hilti::rt::Set<%s>", x);
        }

        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Stream& n) { return CxxTypes{.base_type = "hilti::rt::Stream"}; }

    result_t operator()(const type::Union& n) {
        if ( auto x = n.cxxID() )
            return CxxTypes{.base_type = cxx::Type(*x)};

        auto scope = cxx::ID{cg->unit()->cxxNamespace().namespace_()};
        auto sid = cxx::ID{scope, (n.typeID() ? std::string(*n.typeID()) : fmt("union_%p", &n))};
        auto ns = sid.namespace_();

        if ( cg->prioritizeTypes() )
            cg->unit()->prioritizeType(sid);

        return cache->getOrCreate(
            sid, [&]() { return CxxTypes{.base_type = std::string(sid)}; },
            [&](auto& cxx_types) {
                auto render_body = cxx::Block();
                render_body.addStatement("o << hilti::rt::to_string(x); return o");

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
                cg->addDeclarationFor(n);

                return cxx_types;
            });
    }

    result_t operator()(const type::Vector& n) {
        std::string t;

        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            t = "hilti::rt::vector::Empty";
        else {
            auto x = cg->compile(n.elementType(), codegen::TypeUsage::Storage);

            std::string allocator;
            if ( auto def = cg->typeDefaultValue(n.elementType()) )
                allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

            t = fmt("hilti::rt::Vector<%s%s>", x, allocator);
        }

        return CxxTypes{.base_type = fmt("%s", t)};
    }

    result_t operator()(const type::Time& n) { return CxxTypes{.base_type = "hilti::rt::Time"}; }

    result_t operator()(const type::UnsignedInteger& n) {
        cxx::Type t;

        switch ( n.width() ) {
            case 8:
                t = "hilti::rt::integer::safe<uint8_t>";
                break; // 2 bytes to avoid overloading confusion with uchar_t
            case 16: t = "hilti::rt::integer::safe<uint16_t>"; break;
            case 32: t = "hilti::rt::integer::safe<uint32_t>"; break;
            case 64: t = "hilti::rt::integer::safe<uint64_t>"; break;
            default: logger().internalError("codegen: unexpected integer width", n);
        }

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::Optional& n) {
        std::string t;

        if ( auto ct = n.dereferencedType(); ! ct.isWildcard() )
            t = fmt("std::optional<%s>", cg->compile(ct, codegen::TypeUsage::Storage));
        else
            t = "*";

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::StrongReference& n) {
        std::string t;

        if ( auto ct = n.dereferencedType(); ! ct.isWildcard() )
            t = fmt("hilti::rt::StrongReference<%s>", cg->compile(ct, codegen::TypeUsage::Ctor)); // XXX
        else
            t = "*";

        return CxxTypes{.base_type = t, .param_in = fmt("const %s", t), .param_inout = fmt("%s", t)};
    }

    result_t operator()(const type::stream::View& n) { return CxxTypes{.base_type = "hilti::rt::stream::View"}; }

    result_t operator()(const type::ResolvedID& n) {
        if ( auto x = dispatch(n.type()) )
            return *x;

        logger().internalError(fmt("codegen: ID resolves to type %s, which does not have a visitor",
                                   to_node(n.type()).render()),
                               n);
    }

    result_t operator()(const type::Result& n) {
        std::string t;

        if ( auto ct = n.dereferencedType(); ! ct.isWildcard() )
            t = fmt("hilti::rt::Result<%s>", cg->compile(ct, codegen::TypeUsage::Storage));
        else
            t = "*";

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::String& n) { return CxxTypes{.base_type = "std::string"}; }

    result_t operator()(const type::Struct& n) {
        if ( auto x = n.cxxID() )
            return CxxTypes{.base_type = cxx::Type(*x)};

        auto scope = cxx::ID{cg->unit()->cxxNamespace().namespace_()};
        auto sid = cxx::ID{scope, (n.typeID() ? std::string(*n.typeID()) : fmt("struct_%p", &n))};
        auto ns = sid.namespace_();

        if ( cg->prioritizeTypes() )
            cg->unit()->prioritizeType(sid);

        return cache->getOrCreate(
            sid, [&]() { return CxxTypes{.base_type = std::string(sid)}; },
            [&](auto& cxx_types) {
                auto render_body = cxx::Block();
                render_body.addStatement("o << hilti::rt::to_string(x); return o");

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
                cg->addDeclarationFor(n);

                return cxx_types;
            });
    }

    result_t operator()(const type::Tuple& n) {
        auto x = util::transform(n.types(), [this](auto t) { return cg->compile(t, codegen::TypeUsage::Storage); });
        auto t = fmt("std::tuple<%s>", util::join(x, ", "));
        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::UnresolvedID& n) {
        logger().internalError(fmt("codgen: unresolved type ID %s", n.id()), n);
    }

    result_t operator()(const type::Void& n) { return CxxTypes{.base_type = "void"}; }

    result_t operator()(const type::Computed& n) {
        if ( auto x = dispatch(n.type()) )
            return *x;

        logger()
            .internalError(fmt("codegen: type wrapper (computed) resolves to type %s, which does not have a visitor",
                               to_node(n.type()).render()),
                           n);
    }

    result_t operator()(const type::WeakReference& n) {
        std::string t;

        if ( auto ct = n.dereferencedType(); ! ct.isWildcard() )
            t = fmt("hilti::rt::WeakReference<%s>", cg->compile(ct, codegen::TypeUsage::Ctor));
        else
            t = "*";

        return CxxTypes{.base_type = t};
    }

    result_t operator()(const type::ValueReference& n) {
        std::string t;

        if ( auto ct = n.dereferencedType(); ! ct.isWildcard() ) {
            auto element_type = cg->compile(ct, codegen::TypeUsage::Ctor);
            return CxxTypes{.base_type = fmt("hilti::rt::ValueReference<%s>", element_type), .ctor = element_type};
        }
        else
            return CxxTypes{.base_type = "*"};
    }
};

} // anonymous namespace

cxx::Type CodeGen::compile(const hilti::Type& t, codegen::TypeUsage usage) {
    auto x = VisitorStorage(this, &_cache_types_storage, usage).dispatch(t);

    if ( ! x )
        logger().internalError(fmt("codegen: type %s does not have a visitor", t), t);

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

    if ( ! x )
        logger().internalError(fmt("codegen: type %s does not have a visitor", t), t);

    return std::move(x->default_);
};

std::optional<cxx::declaration::Type> CodeGen::typeDeclaration(const hilti::Type& t) {
    return VisitorDeclaration(this, &_cache_types_declarations).dispatch(t);
};

std::list<cxx::declaration::Type> CodeGen::typeDependencies(const hilti::Type& t) {
    VisitorDeclaration v(this, &_cache_types_declarations);
    v.dispatch(type::effectiveType(t));
    return v.dependencies;
};
