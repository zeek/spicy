// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <cstdio>

#include <hilti/rt/util.h>

#include <hilti/ast/ctors/all.h>
#include <hilti/ast/types/unknown.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using namespace hilti::detail;

using hilti::rt::fmt;

namespace {

struct Visitor : hilti::visitor::PreOrder {
    explicit Visitor(CodeGen* cg) : cg(cg) {}

    CodeGen* cg;

    std::optional<cxx::Expression> result;

    void operator()(ctor::Address* n) final { result = fmt("::hilti::rt::Address(\"%s\")", n->value()); }

    void operator()(ctor::Bitfield* n) final {
        std::vector<cxx::Type> types;
        std::vector<cxx::Expression> values;
        for ( const auto& b : n->btype()->bits(true) ) {
            auto itype = cg->compile(n->btype()->bits(b->id())->itemType(), codegen::TypeUsage::Storage);
            types.emplace_back(itype);

            if ( auto x = n->bits(b->id()) )
                values.emplace_back(cg->compile(x->expression()));
            else
                values.emplace_back("std::nullopt");
        }

        result =
            fmt("hilti::rt::Bitfield<%s>{{}, std::make_tuple(%s)}", util::join(types, ", "), util::join(values, ", "));
    }
    void operator()(ctor::Bool* n) final { result = fmt("::hilti::rt::Bool(%s)", n->value() ? "true" : "false"); }

    void operator()(ctor::Bytes* n) final { result = fmt("\"%s\"_b", util::escapeBytesForCxx(n->value())); }

    void operator()(ctor::Coerced* n) final { result = cg->compile(n->coercedCtor()); }

    void operator()(ctor::Default* n) final {
        std::string args;

        if ( ! n->type()->type()->parameters().empty() ) {
            auto exprs = cg->compileCallArguments(n->typeArguments(), n->type()->type()->parameters());
            args = util::join(exprs, ", ");
        }

        result = fmt("(%s(%s))", cg->compile(n->type(), codegen::TypeUsage::Ctor), args);
    }

    void operator()(ctor::Error* n) final { result = fmt("::hilti::rt::result::Error(\"%s\")", n->value()); }

    void operator()(ctor::Exception* n) final {
        std::string type;

        if ( auto x = n->type()->type()->cxxID() )
            type = x.str();
        else
            type = cg->compile(n->type(), codegen::TypeUsage::Ctor);

        if ( auto x = n->location() )
            result = fmt("%s(%s, %s)", type, cg->compile(n->value()), cg->compile(x));
        else
            result = fmt("%s(%s, \"%s\")", type, cg->compile(n->value()), n->meta().location());
    }

    void operator()(ctor::Interval* n) final {
        result = fmt("::hilti::rt::Interval(hilti::rt::integer::safe<int64_t>(%" PRId64
                     "), hilti::rt::Interval::NanosecondTag())",
                     n->value().nanoseconds());
    }

    void operator()(ctor::Library* n) final {
        result = fmt("%s(%s)", n->type()->type()->as<type::Library>()->cxxName(), cg->compile(n->value()));
    }

    void operator()(ctor::List* n) final {
        if ( n->elementType()->type()->isA<type::Unknown>() )
            // Can only be the empty list.
            result = "::hilti::rt::vector::Empty()";
        else
            result = fmt("::hilti::rt::Vector<%s>({%s})", cg->compile(n->elementType(), codegen::TypeUsage::Storage),
                         util::join(node::transform(n->value(), [this](auto e) { return cg->compile(e); }), ", "));
    }

    void operator()(ctor::Map* n) final {
        if ( n->valueType()->type()->isA<type::Unknown>() ) {
            // Can only be the empty map.
            result = "::hilti::rt::map::Empty()";
            return;
        }

        auto k = cg->compile(n->keyType(), codegen::TypeUsage::Storage);
        auto v = cg->compile(n->valueType(), codegen::TypeUsage::Storage);

        result =
            fmt("::hilti::rt::Map<%s, %s>({%s})", k, v,
                util::join(node::transform(n->value(),
                                           [this](const auto& e) {
                                               return fmt("{%s, %s}", cg->compile(e->key()), cg->compile(e->value()));
                                           }),
                           ", "));
    }

    void operator()(ctor::Network* n) final {
        result = fmt("::hilti::rt::Network(\"%s\", %u)", n->value().prefix(), n->value().length());
    }

    void operator()(ctor::Null* n) final { result = fmt("::hilti::rt::Null()"); }

    void operator()(ctor::Optional* n) final {
        if ( auto e = n->value() )
            result = fmt("std::make_optional(%s)", cg->compile(e));
        else
            result = fmt("std::optional<%s>()", cg->compile(n->dereferencedType(), codegen::TypeUsage::Ctor));
    }

    void operator()(ctor::Port* n) final { result = fmt("::hilti::rt::Port(\"%s\")", n->value()); }

    void operator()(ctor::Real* n) final {
        // We use hexformat for lossless serialization. Older platforms like
        // centos7 have inconsistent support for that in iostreams so we use
        // C99 snprintf instead.
        constexpr size_t size = 256;
        char buf[size];
        std::snprintf(buf, size, "%a", n->value());
        result = buf;
    }

    void operator()(ctor::Result* n) final {
        auto t = cg->compile(n->type(), codegen::TypeUsage::Storage);

        if ( auto e = n->value() )
            result = fmt("%s(%s)", t, cg->compile(e));
        else
            result = fmt("%s(%s)", t, cg->compile(n->error()));
    }

    void operator()(ctor::StrongReference* n) final {
        result =
            fmt("::hilti::rt::StrongReference<%s>()", cg->compile(n->dereferencedType(), codegen::TypeUsage::Ctor));
    }

    void operator()(ctor::RegExp* n) final {
        std::vector<std::string> flags;

        if ( n->isNoSub() )
            flags.emplace_back(".no_sub = true");

        auto t = (n->value().size() == 1 ? "std::string" : "std::vector<std::string>");
        result = fmt("::hilti::rt::RegExp(%s{%s}, {%s})", t,
                     util::join(util::transform(n->value(),
                                                [&](const auto& s) {
                                                    return fmt("\"%s\"", util::escapeUTF8(s, true, false));
                                                }),
                                ", "),
                     util::join(flags, ", "));
    }

    void operator()(ctor::Set* n) final {
        if ( n->elementType()->type()->isA<type::Unknown>() ) {
            // Can only be the empty list.
            result = "::hilti::rt::set::Empty()";
            return;
        }

        const auto k = cg->compile(n->elementType(), codegen::TypeUsage::Storage);

        result =
            fmt("::hilti::rt::Set<%s>({%s})", k,
                util::join(node::transform(n->value(), [this](auto e) { return fmt("%s", cg->compile(e)); }), ", "));
    }

    void operator()(ctor::SignedInteger* n) final {
        if ( /* n.width() == 64 && */ n->value() == INT64_MIN )
            result = fmt("::hilti::rt::integer::safe<std::int64_t>{INT64_MIN}");
        else
            result = fmt("::hilti::rt::integer::safe<std::int%u_t>{%" PRId64 "}", n->width(), n->value());
    }

    void operator()(ctor::Stream* n) final {
        result = fmt("::hilti::rt::Stream(\"%s\"_b)", util::escapeBytesForCxx(n->value()));
    }

    void operator()(ctor::String* n) final {
        if ( n->isLiteral() )
            result = fmt("std::string_view(\"%s\")", util::escapeUTF8(n->value(), true));
        else
            result = fmt("std::string(\"%s\")", util::escapeUTF8(n->value(), true));
    }

    void operator()(ctor::Tuple* n) final {
        result = fmt("std::make_tuple(%s)",
                     util::join(node::transform(n->value(), [this](auto e) { return cg->compile(e); }), ", "));
    }

    void operator()(ctor::Struct* n) final {
        auto id = cg->compile(n->type(), codegen::TypeUsage::Ctor);

        auto is_public_field = [&](auto f) {
            return ! f->type()->type()->template isA<type::Function>() && ! f->isInternal();
        };

        auto convert_field = [&](auto f) {
            if ( auto c = n->field(f->id()) )
                return cg->compile(c->expression());

            return cxx::Expression("{}");
        };

        result = fmt("%s(%s)", id,
                     util::join(node::transform(node::filter(n->type()->type()->as<type::Struct>()->fields(),
                                                             is_public_field),
                                                convert_field),
                                ", "));
    }

    void operator()(ctor::Time* n) final {
        result = fmt("::hilti::rt::Time(%" PRId64 ", hilti::rt::Time::NanosecondTag())", n->value().nanoseconds());
    }

    void operator()(ctor::Enum* n) final {
        auto id = cg->compile(n->type(), codegen::TypeUsage::Storage);
        result = fmt("%s{%s::%s}", id, id, cxx::ID(n->value()->id()));
    }

    void operator()(ctor::ValueReference* n) final {
        result = fmt("::hilti::rt::reference::make_value<%s>(%s)",
                     cg->compile(n->dereferencedType(), codegen::TypeUsage::Ctor), cg->compile(n->expression()));
    }

    void operator()(ctor::Vector* n) final {
        if ( n->elementType()->type()->isA<type::Unknown>() ) {
            // Can only be the empty list.
            result = "::hilti::rt::vector::Empty()";
            return;
        }

        auto x = cg->compile(n->elementType(), codegen::TypeUsage::Storage);

        std::string allocator;
        if ( auto def = cg->typeDefaultValue(n->elementType()) )
            allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

        result =
            fmt("::hilti::rt::Vector<%s%s>({%s})", x, allocator,
                util::join(node::transform(n->value(), [this](auto e) { return fmt("%s", cg->compile(e)); }), ", "));
    }

    void operator()(ctor::UnsignedInteger* n) final {
        result = fmt("::hilti::rt::integer::safe<std::uint%u_t>{%" PRId64 "U}", n->width(), n->value());
    }

    void operator()(ctor::WeakReference* n) final {
        result = fmt("::hilti::rt::WeakReference<%s>()", cg->compile(n->dereferencedType(), codegen::TypeUsage::Ctor));
    }
};

} // anonymous namespace

cxx::Expression CodeGen::compile(Ctor* c, bool lhs) {
    auto v = Visitor(this);
    if ( auto x = hilti::visitor::dispatch(v, c, [](const auto& v) { return v.result; }) )
        return lhs ? _makeLhs(*x, c->type()) : *x;

    logger().internalError(fmt("ctor %s failed to compile", c->typename_()), c);
}
