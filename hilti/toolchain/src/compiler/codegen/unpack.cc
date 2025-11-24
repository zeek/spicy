// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <optional>
#include <ranges>
#include <string>
#include <utility>

#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/integer.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : hilti::visitor::PreOrder {
    enum class Kind { Pack, Unpack };

    Visitor(CodeGen* cg, Kind kind, QualifiedType* src, QualifiedType* data_type, cxx::Expression data,
            const std::vector<cxx::Expression>& args)
        : cg(cg), kind(kind), src(src), data_type(data_type), data(std::move(data)), args(args) {}

    CodeGen* cg;
    Kind kind;
    QualifiedType* src;
    QualifiedType* data_type;
    cxx::Expression data;
    const std::vector<cxx::Expression>& args;

    std::optional<std::string> result;

    auto kindToString() const {
        switch ( kind ) {
            case Kind::Pack: return "pack";
            case Kind::Unpack: return "unpack";
        }

        util::cannotBeReached();
    }

    void operator()(type::Address* n) final {
        switch ( kind ) {
            case Kind::Pack: result = fmt("::hilti::rt::address::pack(%s, %s)", data, args[0]); return;
            case Kind::Unpack: result = fmt("::hilti::rt::address::unpack(%s, %s, %s)", data, args[0], args[1]); return;
        }

        util::cannotBeReached();
    }

    void operator()(type::Bitfield* n) final {
        assert(kind == Kind::Unpack); // packing not supported (yet?)

        auto bitorder = cxx::Expression("::hilti::rt::integer::BitOrder::LSB0");
        if ( args.size() > 1 )
            bitorder = args[1];

        auto unpacked = cg->addTmp(
            "x",
            cxx::Type(util::fmt("::hilti::rt::Result<::hilti::rt::Tuple<::hilti::rt::integer::safe<uint%d_t>, %s>>",
                                n->width(), cg->compile(data_type, codegen::TypeUsage::Storage))));
        auto unpack_uint =
            fmt("%s = ::hilti::rt::integer::unpack<uint%d_t>(%s, %s)", unpacked, n->width(), data, args[0]);

        auto bf_value = cg->unsignedIntegerToBitfield(src, fmt("::hilti::rt::tuple::get<0>(*%s)", unpacked), bitorder);
        result = fmt("(%s, ::hilti::rt::make_result(::hilti::rt::tuple::make(%s, ::hilti::rt::tuple::get<1>(*%s))))",
                     unpack_uint, bf_value, unpacked);
    }

    void operator()(type::UnsignedInteger* n) final {
        result = fmt("::hilti::rt::integer::%s<uint%d_t>(%s, %s)", kindToString(), n->width(), data, args[0]);
    }

    void operator()(type::SignedInteger* n) final {
        result = fmt("::hilti::rt::integer::%s<int%d_t>(%s, %s)", kindToString(), n->width(), data, args[0]);
    }

    void operator()(type::Real* n) final {
        result = fmt("::hilti::rt::real::%s(%s, %s, %s)", kindToString(), data, args[0], args[1]);
    }
};

} // anonymous namespace

cxx::Expression CodeGen::pack(Expression* data, const Expressions& args) {
    auto cxx_args = util::toVector(std::ranges::transform_view(args, [&](const auto& e) { return compile(e, false); }));
    auto v = Visitor(this, Visitor::Kind::Pack, data->type(), nullptr, compile(data), cxx_args);
    if ( auto result =
             hilti::visitor::dispatch(v, data->type()->type(), [](const auto& v) -> const auto& { return v.result; }) )
        return cxx::Expression(*result);

    logger().internalError("pack failed to compile", data->type());
}

cxx::Expression CodeGen::pack(QualifiedType* t, const cxx::Expression& data, const std::vector<cxx::Expression>& args) {
    auto v = Visitor(this, Visitor::Kind::Pack, t, nullptr, data, args);
    if ( auto result = hilti::visitor::dispatch(v, t->type(), [](const auto& v) -> const auto& { return v.result; }) )
        return cxx::Expression(*result);

    logger().internalError("pack failed to compile", t);
}

cxx::Expression CodeGen::unpack(QualifiedType* t, QualifiedType* data_type, Expression* data, const Expressions& args,
                                bool throw_on_error) {
    auto cxx_args = util::toVector(std::ranges::transform_view(args, [&](const auto& e) { return compile(e, false); }));
    auto v = Visitor(this, Visitor::Kind::Unpack, t, data_type, compile(data), cxx_args);
    if ( auto result = hilti::visitor::dispatch(v, t->type(), [](const auto& v) -> const auto& { return v.result; }) ) {
        if ( throw_on_error )
            return cxx::Expression(util::fmt("%s.valueOrThrow()", *result));
        else
            return cxx::Expression(*result);
    }

    logger().internalError("unpack failed to compile", t);
}

cxx::Expression CodeGen::unpack(QualifiedType* t, QualifiedType* data_type, const cxx::Expression& data,
                                const std::vector<cxx::Expression>& args, bool throw_on_error) {
    auto v = Visitor(this, Visitor::Kind::Unpack, t, data_type, data, args);
    if ( auto result = hilti::visitor::dispatch(v, t->type(), [](const auto& v) -> const auto& { return v.result; }) ) {
        if ( throw_on_error )
            return cxx::Expression(util::fmt("%s.valueOrThrow<::hilti::rt::InvalidValue>()", *result));
        else
            return cxx::Expression(*result);
    }

    logger().internalError("unpack failed to compile", t);
}
