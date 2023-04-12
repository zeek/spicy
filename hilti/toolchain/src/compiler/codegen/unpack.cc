// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : hilti::visitor::PreOrder<std::string, Visitor> {
    enum class Kind { Pack, Unpack };

    Visitor(CodeGen* cg, Kind kind, cxx::Expression data, const std::vector<cxx::Expression>& args)
        : cg(cg), kind(kind), data(std::move(data)), args(args) {}
    CodeGen* cg;
    Kind kind;
    cxx::Expression data;
    const std::vector<cxx::Expression>& args;

    auto kindToString() const {
        switch ( kind ) {
            case Kind::Pack: return "pack";
            case Kind::Unpack: return "unpack";
        }

        util::cannot_be_reached();
    }

    result_t operator()(const type::Address& n) {
        switch ( kind ) {
            case Kind::Pack: return fmt("::hilti::rt::address::pack(%s, %s)", data, args[0]);
            case Kind::Unpack: return fmt("::hilti::rt::address::unpack(%s, %s, %s)", data, args[0], args[1]);
        }

        util::cannot_be_reached();
    }

    result_t operator()(const type::UnsignedInteger& n) {
        return fmt("::hilti::rt::integer::%s<uint%d_t>(%s, %s)", kindToString(), n.width(), data, args[0]);
    }

    result_t operator()(const type::SignedInteger& n) {
        return fmt("::hilti::rt::integer::%s<int%d_t>(%s, %s)", kindToString(), n.width(), data, args[0]);
    }

    result_t operator()(const type::Real& n) {
        return fmt("::hilti::rt::real::%s(%s, %s, %s)", kindToString(), data, args[0], args[1]);
    }
};

} // anonymous namespace

cxx::Expression CodeGen::pack(const Expression& data, const std::vector<Expression>& args) {
    auto cxx_args = util::transform(args, [&](const auto& e) { return compile(e, false); });
    if ( auto x = Visitor(this, Visitor::Kind::Pack, compile(data), cxx_args).dispatch(data.type()) )
        return cxx::Expression(*x);

    logger().internalError("pack failed to compile", data.type());
}

cxx::Expression CodeGen::pack(const hilti::Type& t, const cxx::Expression& data,
                              const std::vector<cxx::Expression>& args) {
    if ( auto x = Visitor(this, Visitor::Kind::Pack, data, args).dispatch(t) )
        return cxx::Expression(*x);

    logger().internalError("pack failed to compile", t);
}

cxx::Expression CodeGen::unpack(const hilti::Type& t, const Expression& data, const std::vector<Expression>& args, bool throw_on_error) {
    auto cxx_args = util::transform(args, [&](const auto& e) { return compile(e, false); });
    if ( auto x = Visitor(this, Visitor::Kind::Unpack, compile(data), cxx_args).dispatch(t) ) {
        if ( throw_on_error )
            return cxx::Expression(util::fmt("%s.valueOrThrow()", *x));
        else
            return cxx::Expression(*x);
    }

    logger().internalError("unpack failed to compile", t);
}

cxx::Expression CodeGen::unpack(const hilti::Type& t, const cxx::Expression& data,
                                const std::vector<cxx::Expression>& args, bool throw_on_error) {
    if ( auto x = Visitor(this, Visitor::Kind::Unpack, data, args).dispatch(t) ) {
        if ( throw_on_error )
            return cxx::Expression(util::fmt("%s.valueOrThrow<::hilti::rt::InvalidValue>()", *x));
        else
            return cxx::Expression(*x);
    }

    logger().internalError("unpack failed to compile", t);
}
