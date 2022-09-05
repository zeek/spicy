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
    Visitor(CodeGen* cg, cxx::Expression data, const std::vector<cxx::Expression>& args)
        : cg(cg), data(std::move(data)), args(args) {}
    CodeGen* cg;
    cxx::Expression data;
    const std::vector<cxx::Expression>& args;

    std::optional<std::string> _result;

    result_t operator()(const type::Address& n, type::Visitor::position_t&) override {
        _result = fmt("::hilti::rt::address::unpack(%s, %s, %s)", data, args[0], args[1]);
    }

    result_t operator()(const type::UnsignedInteger& n, type::Visitor::position_t&) override {
        _result = fmt("::hilti::rt::integer::unpack<uint%d_t>(%s, %s)", n.width(), data, args[0]);
    }

    result_t operator()(const type::SignedInteger& n, type::Visitor::position_t&) override {
        _result = fmt("::hilti::rt::integer::unpack<int%d_t>(%s, %s)", n.width(), data, args[0]);
    }

    result_t operator()(const type::Real& n, type::Visitor::position_t&) override {
        _result = fmt("::hilti::rt::real::unpack(%s, %s, %s)", data, args[0], args[1]);
    }
};

} // anonymous namespace

cxx::Expression CodeGen::unpack(const hilti::Type& t, const Expression& data, const std::vector<Expression>& args) {
    auto cxx_args = util::transform(args, [&](const auto& e) { return compile(e, false); });
    auto v = Visitor(this, compile(data), cxx_args);
    if ( v.dispatch(t); v._result )
        return cxx::Expression(*v._result);

    logger().internalError("unpack failed to compile", t);
}

cxx::Expression CodeGen::unpack(const hilti::Type& t, const cxx::Expression& data,
                                const std::vector<cxx::Expression>& args) {
    auto v = Visitor(this, data, args);
    if ( v.dispatch(t); v._result )
        return cxx::Expression(*v._result);

    logger().internalError("unpack failed to compile", t);
}
