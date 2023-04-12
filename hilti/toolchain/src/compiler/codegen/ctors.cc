// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <cstdio>

#include <hilti/rt/util.h>

#include <hilti/ast/ctors/all.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using namespace hilti::detail;

using hilti::rt::fmt;

namespace {

struct Visitor : hilti::visitor::PreOrder<cxx::Expression, Visitor> {
    explicit Visitor(CodeGen* cg) : cg(cg) {}
    CodeGen* cg;

    result_t operator()(const ctor::Address& n) { return fmt("::hilti::rt::Address(\"%s\")", n.value()); }

    result_t operator()(const ctor::Bool& n) { return fmt("::hilti::rt::Bool(%s)", n.value() ? "true" : "false"); }

    result_t operator()(const ctor::Bytes& n) { return fmt("\"%s\"_b", util::escapeBytesForCxx(n.value())); }

    result_t operator()(const ctor::Coerced& n) { return cg->compile(n.coercedCtor()); }

    result_t operator()(const ctor::Default& n) {
        std::string args;

        if ( type::takesArguments(n.type()) ) {
            auto exprs = cg->compileCallArguments(n.typeArguments(), n.type().parameters());
            args = util::join(exprs, ", ");
        }

        return fmt("(%s(%s))", cg->compile(n.type(), codegen::TypeUsage::Ctor), args);
    }

    result_t operator()(const ctor::Error& n) { return fmt("::hilti::rt::result::Error(\"%s\")", n.value()); }

    result_t operator()(const ctor::Exception& n) {
        std::string type;

        if ( auto x = n.type().cxxID() )
            type = x->str();
        else
            type = cg->compile(n.type(), codegen::TypeUsage::Ctor);

        return fmt("%s(%s, \"%s\")", type, cg->compile(n.value()), n.meta().location());
    }

    result_t operator()(const ctor::Interval& n) {
        return fmt("::hilti::rt::Interval(hilti::rt::integer::safe<int64_t>(%" PRId64
                   "), hilti::rt::Interval::NanosecondTag())",
                   n.value().nanoseconds());
    }

    result_t operator()(const ctor::Library& n) {
        return fmt("%s(%s)", n.type().as<type::Library>().cxxName(), cg->compile(n.value()));
    }

    result_t operator()(const ctor::List& n) {
        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            return "::hilti::rt::vector::Empty()";

        return fmt("::hilti::rt::Vector<%s>({%s})", cg->compile(n.elementType(), codegen::TypeUsage::Storage),
                   util::join(node::transform(n.value(), [this](auto e) { return cg->compile(e); }), ", "));
    }

    result_t operator()(const ctor::Map& n) {
        if ( n.valueType() == type::unknown )
            // Can only be the empty map.
            return "::hilti::rt::map::Empty()";

        auto k = cg->compile(n.keyType(), codegen::TypeUsage::Storage);
        auto v = cg->compile(n.valueType(), codegen::TypeUsage::Storage);

        return fmt("::hilti::rt::Map<%s, %s>({%s})", k, v,
                   util::join(node::transform(n.value(),
                                              [this](const auto& e) {
                                                  return fmt("{%s, %s}", cg->compile(e.key()), cg->compile(e.value()));
                                              }),
                              ", "));
    }

    result_t operator()(const ctor::Network& n) {
        return fmt("::hilti::rt::Network(\"%s\", %u)", n.value().prefix(), n.value().length());
    }

    result_t operator()(const ctor::Null& n) { return fmt("::hilti::rt::Null()"); }

    result_t operator()(const ctor::Optional& n) {
        if ( auto e = n.value() )
            return fmt("std::make_optional(%s)", cg->compile(*e));

        return fmt("std::optional<%s>()", cg->compile(n.dereferencedType(), codegen::TypeUsage::Ctor));
    }

    result_t operator()(const ctor::Port& n) { return fmt("::hilti::rt::Port(\"%s\")", n.value()); }

    result_t operator()(const ctor::Real& n) {
        // We use hexformat for lossless serialization. Older platforms like
        // centos7 have inconsistent support for that in iostreams so we use
        // C99 snprintf instead.
        constexpr size_t size = 256;
        char buf[size];
        std::snprintf(buf, size, "%a", n.value());
        return buf;
    }

    result_t operator()(const ctor::Result& n) {
        auto t = cg->compile(n.type(), codegen::TypeUsage::Storage);

        if ( auto e = n.value() )
            return fmt("%s(%s)", t, cg->compile(*e));

        return fmt("%s(%s)", t, cg->compile(*n.error()));
    }

    result_t operator()(const ctor::StrongReference& n) {
        return fmt("::hilti::rt::StrongReference<%s>()", cg->compile(n.dereferencedType(), codegen::TypeUsage::Ctor));
    }

    result_t operator()(const ctor::RegExp& n) {
        std::vector<std::string> flags;

        if ( n.isNoSub() )
            flags.emplace_back(".no_sub = true");

        auto t = (n.value().size() == 1 ? "std::string" : "std::vector<std::string>");
        return fmt("::hilti::rt::RegExp(%s{%s}, {%s})", t,
                   util::join(util::transform(n.value(),
                                              [&](const auto& s) {
                                                  return fmt("\"%s\"", util::escapeUTF8(s, true, false));
                                              }),
                              ", "),
                   util::join(flags, ", "));
    }

    result_t operator()(const ctor::Set& n) {
        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            return "::hilti::rt::set::Empty()";

        const auto k = cg->compile(n.elementType(), codegen::TypeUsage::Storage);

        return fmt("::hilti::rt::Set<%s>({%s})", k,
                   util::join(node::transform(n.value(), [this](auto e) { return fmt("%s", cg->compile(e)); }), ", "));
    }

    result_t operator()(const ctor::SignedInteger& n) {
        if ( /* n.width() == 64 && */ n.value() == INT64_MIN )
            return fmt("::hilti::rt::integer::safe<std::int64_t>{INT64_MIN}");

        return fmt("::hilti::rt::integer::safe<std::int%u_t>{%" PRId64 "}", n.width(), n.value());
    }

    result_t operator()(const ctor::Stream& n) {
        return fmt("::hilti::rt::Stream(\"%s\"_b)", util::escapeBytesForCxx(n.value()));
    }

    result_t operator()(const ctor::String& n) { return fmt("std::string(\"%s\")", util::escapeUTF8(n.value(), true)); }

    result_t operator()(const ctor::Tuple& n) {
        return fmt("std::make_tuple(%s)",
                   util::join(node::transform(n.value(), [this](auto e) { return cg->compile(e); }), ", "));
    }

    result_t operator()(const ctor::Struct& n) {
        auto id = cg->compile(n.type(), codegen::TypeUsage::Ctor);

        auto is_public_field = [&](auto f) { return ! f.type().template isA<type::Function>() && ! f.isInternal(); };

        auto convert_field = [&](auto f) {
            if ( auto c = n.field(f.id()) )
                return cg->compile(c->expression());

            return cxx::Expression("{}");
        };

        return fmt("%s(%s)", id,
                   util::join(node::transform(node::filter(n.type().as<type::Struct>().fields(), is_public_field),
                                              convert_field),
                              ", "));
    }

    result_t operator()(const ctor::Time& n) {
        return fmt("::hilti::rt::Time(%" PRId64 ", hilti::rt::Time::NanosecondTag())", n.value().nanoseconds());
    }

    result_t operator()(const ctor::Enum& n) {
        auto id = cg->compile(n.type(), codegen::TypeUsage::Storage);
        return fmt("%s{%s::%s}", id, id, cxx::ID(n.value().id()));
    }

    result_t operator()(const ctor::ValueReference& n) {
        return fmt("::hilti::rt::reference::make_value<%s>(%s)",
                   cg->compile(n.dereferencedType(), codegen::TypeUsage::Ctor), cg->compile(n.expression()));
    }

    result_t operator()(const ctor::Vector& n) {
        if ( n.elementType() == type::unknown )
            // Can only be the empty list.
            return "::hilti::rt::vector::Empty()";

        auto x = cg->compile(n.elementType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n.elementType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        return fmt("::hilti::rt::Vector<%s%s>({%s})", x, allocator,
                   util::join(node::transform(n.value(), [this](auto e) { return fmt("%s", cg->compile(e)); }), ", "));
    }

    result_t operator()(const ctor::UnsignedInteger& n) {
        return fmt("::hilti::rt::integer::safe<std::uint%u_t>{%" PRId64 "U}", n.width(), n.value());
    }

    result_t operator()(const ctor::WeakReference& n) {
        return fmt("::hilti::rt::WeakReference<%s>()", cg->compile(n.dereferencedType(), codegen::TypeUsage::Ctor));
    }
};

} // anonymous namespace

cxx::Expression CodeGen::compile(const hilti::Ctor& c, bool lhs) {
    if ( auto x = Visitor(this).dispatch(c) )
        return lhs ? _makeLhs(*x, c.type()) : *x;

    logger().internalError(fmt("ctor %s failed to compile", to_node(c).typename_()), c);
}
