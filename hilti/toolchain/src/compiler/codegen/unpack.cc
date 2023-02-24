// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <optional>
#include <string>
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

struct Visitor : hilti::visitor::PreOrder<void, Visitor>, type::Visitor {
    enum class Kind { Pack, Unpack };

    Visitor(CodeGen* cg, Kind kind, cxx::Expression data, const std::vector<cxx::Expression>& args)
        : cg(cg), kind(kind), data(std::move(data)), args(args) {}
    CodeGen* cg;
    Kind kind;
    cxx::Expression data;
    const std::vector<cxx::Expression>& args;

    std::optional<std::string> _result;

    auto kindToString() const {
        switch ( kind ) {
            case Kind::Pack: return "pack";
            case Kind::Unpack: return "unpack";
        }

        util::cannot_be_reached();
    }

    result_t operator()(const type::Address& n, type::Visitor::position_t&) override {
        switch ( kind ) {
            case Kind::Pack: {
                _result = fmt("::hilti::rt::address::pack(%s, %s)", data, args[0]);
                break;
            }
            case Kind::Unpack: {
                _result = fmt("::hilti::rt::address::unpack(%s, %s, %s)", data, args[0], args[1]);
                break;
            }
        }
    }

    result_t operator()(const type::UnsignedInteger& n, type::Visitor::position_t&) override {
        _result = fmt("::hilti::rt::integer::%s<uint%d_t>(%s, %s)", kindToString(), n.width(), data, args[0]);
    }

    result_t operator()(const type::SignedInteger& n, type::Visitor::position_t&) override {
        _result = fmt("::hilti::rt::integer::%s<int%d_t>(%s, %s)", kindToString(), n.width(), data, args[0]);
    }

    result_t operator()(const type::Real& n, type::Visitor::position_t&) override {
        _result = fmt("::hilti::rt::real::%s(%s, %s, %s)", kindToString(), data, args[0], args[1]);
    }
};

} // anonymous namespace

cxx::Expression CodeGen::pack(const Expression& data, const std::vector<Expression>& args) {
    auto cxx_args = util::transform(args, [&](const auto& e) { return compile(e, false); });
    auto v = Visitor(this, Visitor::Kind::Pack, compile(data), cxx_args);
    if ( v.dispatch(data.type()); v._result )
        return cxx::Expression(*v._result);

    logger().internalError("pack failed to compile", data.type());
}

cxx::Expression CodeGen::pack(const hilti::Type& t, const cxx::Expression& data,
                              const std::vector<cxx::Expression>& args) {
    auto v = Visitor(this, Visitor::Kind::Pack, data, args);
    if ( v.dispatch(t); v._result )
        return cxx::Expression(*v._result);

    logger().internalError("pack failed to compile", t);
}

cxx::Expression CodeGen::unpack(const hilti::Type& t, const Expression& data, const std::vector<Expression>& args,
                                bool throw_on_error) {
    auto cxx_args = util::transform(args, [&](const auto& e) { return compile(e, false); });
    auto v = Visitor(this, Visitor::Kind::Unpack, compile(data), cxx_args);
    if ( v.dispatch(t); v._result ) {
        if ( throw_on_error )
            return cxx::Expression(util::fmt("%s.valueOrThrow()", *v._result));
        else
            return cxx::Expression(*v._result);
    }

    logger().internalError("unpack failed to compile", t);
}

cxx::Expression CodeGen::unpack(const hilti::Type& t, const cxx::Expression& data,
                                const std::vector<cxx::Expression>& args, bool throw_on_error) {
    auto v = Visitor(this, Visitor::Kind::Unpack, data, args);
    if ( v.dispatch(t); v._result ) {
        if ( throw_on_error )
            return cxx::Expression(util::fmt("%s.valueOrThrow<::hilti::rt::InvalidValue>()", *v._result));
        else
            return cxx::Expression(*v._result);
    }

    logger().internalError("unpack failed to compile", t);
}
