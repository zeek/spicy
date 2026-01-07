// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <ranges>

#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/operators/all.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/ast-dumper.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : hilti::visitor::PreOrder {
    Visitor(CodeGen* cg, bool lhs) : cg(cg), lhs(lhs) {}
    CodeGen* cg;
    bool lhs;

    std::optional<cxx::Expression> result;

    // Helpers

    cxx::Expression op0(const expression::ResolvedOperator* o) { return cg->compile(o->op0()); }

    cxx::Expression op1(const expression::ResolvedOperator* o) { return cg->compile(o->op1()); }

    cxx::Expression op2(const expression::ResolvedOperator* o) { return cg->compile(o->op2()); }

    cxx::Expression binary(const expression::ResolvedOperator* o, const std::string& x) {
        return fmt("%s %s %s", op0(o), x, op1(o));
    }

    auto compileExpressions(const Expressions& exprs) {
        return util::toVector(exprs | std::views::transform([&](auto e) { return cg->compile(e); }));
    }

    auto compileExpressions(const node::Range<Expression>& exprs) {
        return util::toVector(exprs | std::views::transform([&](auto e) { return cg->compile(e); }));
    }

    auto methodArguments(const expression::ResolvedOperator* o) {
        auto* ops = o->op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto* coerced = ops->tryAs<expression::Coerced>() )
            ops = coerced->expression();

        if ( auto* ctor_ = ops->tryAs<expression::Ctor>() ) {
            auto* ctor = ctor_->ctor();

            // If the argument was the result of a coercion unpack its result.
            if ( auto* x = ctor->tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto* args = ctor->tryAs<ctor::Tuple>() )
                return std::make_pair(op0(o), compileExpressions(args->value()));
        }

        util::cannotBeReached();
    }

    auto tupleArguments(expression::ResolvedOperator* o, Expression* op) {
        auto* ctor = op->as<expression::Ctor>()->ctor();

        if ( auto* x = ctor->tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return compileExpressions(ctor->as<ctor::Tuple>()->value());
    }

    auto tupleArgumentType(Expression* op, int i) {
        auto* ctor = op->as<expression::Ctor>()->ctor();

        if ( auto* x = ctor->tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor->as<ctor::Tuple>()->value()[i]->type();
    }

    auto optionalArgument(const std::vector<cxx::Expression>& args, unsigned int i) {
        return i < args.size() ? std::string(args[i]) : "";
    }

    std::optional<cxx::Expression> optionalArgument(const Expressions& args, unsigned int i) {
        if ( i < args.size() )
            return cg->compile(args[i], false);

        return {};
    }

    /// Address

    void operator()(operator_::address::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::address::Unequal* n) final { result = binary(n, "!="); }
    void operator()(operator_::address::Family* n) final { result = fmt("%s.family()", op0(n)); }

    /// Bool

    void operator()(operator_::bool_::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::bool_::Unequal* n) final { result = binary(n, "!="); }
    void operator()(operator_::bool_::BitAnd* n) final { result = binary(n, "&"); }
    void operator()(operator_::bool_::BitOr* n) final { result = binary(n, "|"); }
    void operator()(operator_::bool_::BitXor* n) final { result = binary(n, "^"); }

    /// Bitfield

    void operator()(operator_::bitfield::Member* n) final {
        const auto& id = n->op1()->as<expression::Member>()->id();
        auto elem = n->op0()->type()->type()->as<type::Bitfield>()->bitsIndex(id);
        assert(elem);
        result = {fmt("(::hilti::rt::tuple::get<%u>(%s.value))", *elem, op0(n)), Side::RHS};
    }

    void operator()(operator_::bitfield::HasMember* n) final {
        const auto& id = n->op1()->as<expression::Member>()->id();
        auto elem = n->op0()->type()->type()->as<type::Bitfield>()->bitsIndex(id);
        assert(elem);
        result = {fmt("%s.value.hasValue(%s)", op0(n), *elem), Side::RHS};
    }

    /// bytes::Iterator

    void operator()(operator_::bytes::iterator::Deref* n) final { result = {fmt("*%s", op0(n)), Side::LHS}; }
    void operator()(operator_::bytes::iterator::IncrPostfix* n) final { result = fmt("%s++", op0(n)); }
    void operator()(operator_::bytes::iterator::IncrPrefix* n) final { result = fmt("++%s", op0(n)); }
    void operator()(operator_::bytes::iterator::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::iterator::Lower* n) final { result = fmt("%s < %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::iterator::LowerEqual* n) final { result = fmt("%s <= %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::iterator::Greater* n) final { result = fmt("%s > %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::iterator::GreaterEqual* n) final { result = fmt("%s >= %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::iterator::Difference* n) final { result = fmt("%s - %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::iterator::Sum* n) final { result = fmt("%s + %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::iterator::SumAssign* n) final { result = fmt("%s += %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::iterator::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    // Bytes

    void operator()(operator_::bytes::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::Greater* n) final { result = fmt("%s > %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::GreaterEqual* n) final { result = fmt("%s >= %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::Lower* n) final { result = fmt("%s < %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::LowerEqual* n) final { result = fmt("%s <= %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::Size* n) final { result = fmt("%s.size()", op0(n)); }
    void operator()(operator_::bytes::Sum* n) final { result = fmt("%s + %s", op0(n), op1(n)); }
    void operator()(operator_::bytes::SumAssignBytes* n) final { result = fmt("%s.append(%s)", op0(n), op1(n)); }
    void operator()(operator_::bytes::SumAssignStreamView* n) final { result = fmt("%s.append(%s)", op0(n), op1(n)); }
    void operator()(operator_::bytes::SumAssignUInt8* n) final { result = fmt("%s.append(%s)", op0(n), op1(n)); }
    void operator()(operator_::bytes::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::bytes::In* n) final {
        result = fmt("::hilti::rt::tuple::get<0>(%s.find(%s))", op1(n), op0(n));
    }

    void operator()(operator_::bytes::Find* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.find(%s)", self, args[0]);
    }

    void operator()(operator_::bytes::LowerCase* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.lower(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::bytes::UpperCase* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.upper(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::bytes::At* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.at(%s)", self, args[0]);
    }

    void operator()(operator_::bytes::Split* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.split(%s)", self, optionalArgument(args, 0));
    }

    void operator()(operator_::bytes::Split1* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.split1(%s)", self, optionalArgument(args, 0));
    }

    void operator()(operator_::bytes::StartsWith* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.startsWith(%s)", self, args[0]);
    }

    void operator()(operator_::bytes::EndsWith* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.endsWith(%s)", self, args[0]);
    }

    void operator()(operator_::bytes::Strip* n) final {
        auto [self, args] = methodArguments(n);

        std::string x;

        if ( auto side = optionalArgument(args, 1); ! side.empty() )
            x = std::move(side);

        if ( auto set = optionalArgument(args, 0); ! set.empty() ) {
            if ( x.size() )
                x += ", ";

            x += set;
        }

        result = fmt("%s.strip(%s)", self, x);
    }

    void operator()(operator_::bytes::SubIterators* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::bytes::SubIterator* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.sub(%s)", self, args[0]);
    }

    void operator()(operator_::bytes::SubOffsets* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::bytes::Join* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.join(%s)", self, args[0]);
    }

    void operator()(operator_::bytes::ToIntAscii* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.toInt(%s)", self, optionalArgument(args, 0));
    }

    void operator()(operator_::bytes::ToUIntAscii* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.toUInt(%s)", self, optionalArgument(args, 0));
    }

    void operator()(operator_::bytes::ToIntBinary* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.toInt(%s)", self, optionalArgument(args, 0));
    }

    void operator()(operator_::bytes::ToUIntBinary* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.toUInt(%s)", self, optionalArgument(args, 0));
    }

    void operator()(operator_::bytes::ToRealAscii* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.toReal()", self);
    }

    void operator()(operator_::bytes::ToTimeAscii* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.toTime(%s)", self, optionalArgument(args, 0));
    }

    void operator()(operator_::bytes::ToTimeBinary* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.toTime(%s)", self, optionalArgument(args, 0));
    }

    void operator()(operator_::bytes::Decode* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.decode(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::bytes::Match* n) final {
        auto [self, args] = methodArguments(n);

        std::string group;

        if ( auto x = optionalArgument(args, 1); ! x.empty() )
            group = fmt(", %s", x);

        result = fmt("%s.match(%s%s)", self, args[0], group);
    }

    // Enum

    void operator()(operator_::enum_::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::enum_::Unequal* n) final { result = binary(n, "!="); }

    void operator()(operator_::enum_::CastToSignedInteger* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s.value())", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::enum_::CastToUnsignedInteger* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s.value())", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::enum_::CtorSigned* n) final {
        auto args = tupleArguments(n, n->op1());
        auto* t = n->op0()->type();
        result = fmt("%s{%s}", cg->compile(t, codegen::TypeUsage::Storage), args[0]);
    }

    void operator()(operator_::enum_::CtorUnsigned* n) final {
        auto args = tupleArguments(n, n->op1());
        auto* t = n->op0()->type();
        result = fmt("%s{%s}", cg->compile(t, codegen::TypeUsage::Storage), args[0]);
    }

    void operator()(operator_::enum_::HasLabel* n) final {
        result = fmt("::hilti::rt::enum_::has_label(%s, %s)", op0(n), cg->typeInfo(n->op0()->type()));
    }

    // Error

    void operator()(operator_::error::Ctor* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::result::Error(%s)", args[0]);
    }

    void operator()(operator_::error::Equal* n) final { result = binary(n, "=="); }

    void operator()(operator_::error::Unequal* n) final { result = binary(n, "!="); }

    // Exception

    void operator()(operator_::exception::Ctor* n) final {
        std::string type;

        auto args = tupleArguments(n, n->op1());

        if ( auto x = n->op0()->type()->type()->cxxID() )
            type = x.str();
        else
            type = cg->compile(n->op0()->type(), codegen::TypeUsage::Ctor);

        result = fmt("%s(%s)", type, args[0]);
    }

    void operator()(operator_::exception::Description* n) final { result = fmt("%s.description()", op0(n)); }

    // Function

    void operator()(operator_::function::Call* n) final {
        // 1st operand directly references a function, validator ensures that.
        auto* decl = cg->context()->astContext()->lookup(n->op0()->as<expression::Name>()->resolvedDeclarationIndex());
        auto* f = decl->as<declaration::Function>();

        auto name = op0(n);

        if ( auto* a = f->function()->attributes()->find(hilti::attribute::kind::Cxxname) ) {
            if ( auto s = a->valueAsString() )
                name = cxx::Expression(*s);
            else
                logger().error(s.error(), n->location());
        }

        const auto& values = n->op1()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();
        result = fmt("%s(%s)", name,
                     util::join(cg->compileCallArguments(values, f->function()->ftype()->parameters()), ", "));
    }

    // Interval

    void operator()(operator_::interval::Difference* n) final { result = binary(n, "-"); }
    void operator()(operator_::interval::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::interval::Greater* n) final { result = binary(n, ">"); }
    void operator()(operator_::interval::GreaterEqual* n) final { result = binary(n, ">="); }
    void operator()(operator_::interval::Lower* n) final { result = binary(n, "<"); }
    void operator()(operator_::interval::LowerEqual* n) final { result = binary(n, "<="); }
    void operator()(operator_::interval::MultipleUnsignedInteger* n) final { result = binary(n, "*"); }
    void operator()(operator_::interval::MultipleReal* n) final { result = binary(n, "*"); }
    void operator()(operator_::interval::Nanoseconds* n) final { result = fmt("%s.nanoseconds()", op0(n)); }
    void operator()(operator_::interval::Seconds* n) final { result = fmt("%s.seconds()", op0(n)); }
    void operator()(operator_::interval::Sum* n) final { result = binary(n, "+"); }
    void operator()(operator_::interval::Unequal* n) final { result = binary(n, "!="); }

    void operator()(operator_::interval::CtorSignedIntegerSecs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Interval(%s, ::hilti::rt::Interval::SecondTag())", args[0]);
    }

    void operator()(operator_::interval::CtorSignedIntegerNs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Interval(%s, ::hilti::rt::Interval::NanosecondTag())", args[0]);
    }

    void operator()(operator_::interval::CtorUnsignedIntegerSecs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Interval(%s, ::hilti::rt::Interval::SecondTag())", args[0]);
    }

    void operator()(operator_::interval::CtorUnsignedIntegerNs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Interval(%s, ::hilti::rt::Interval::NanosecondTag())", args[0]);
    }

    void operator()(operator_::interval::CtorRealSecs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Interval(%f, ::hilti::rt::Interval::SecondTag())", args[0]);
    }

    // List
    void operator()(operator_::list::iterator::IncrPostfix* n) final { result = fmt("%s++", op0(n)); }
    void operator()(operator_::list::iterator::IncrPrefix* n) final { result = fmt("++%s", op0(n)); }
    void operator()(operator_::list::iterator::Deref* n) final { result = {fmt("*%s", op0(n)), Side::LHS}; }
    void operator()(operator_::list::iterator::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::list::iterator::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::list::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::list::Size* n) final { result = fmt("%s.size()", op0(n)); }
    void operator()(operator_::list::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    // Map

    void operator()(operator_::map::iterator::IncrPostfix* n) final { result = fmt("%s++", op0(n)); }
    void operator()(operator_::map::iterator::IncrPrefix* n) final { result = fmt("++%s", op0(n)); }
    void operator()(operator_::map::iterator::Deref* n) final { result = {fmt("*%s", op0(n)), Side::LHS}; }
    void operator()(operator_::map::iterator::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::map::iterator::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::map::Delete* n) final { result = fmt("%s.erase(%s)", op0(n), op1(n)); }
    void operator()(operator_::map::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::map::In* n) final { result = fmt("%s.contains(%s)", op1(n), op0(n)); }
    void operator()(operator_::map::IndexConst* n) final { result = {fmt("%s[%s]", op0(n), op1(n)), Side::LHS}; }
    void operator()(operator_::map::IndexNonConst* n) final { result = {fmt("%s[%s]", op0(n), op1(n)), Side::LHS}; }
    void operator()(operator_::map::Size* n) final { result = fmt("%s.size()", op0(n)); }
    void operator()(operator_::map::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::map::Get* n) final {
        auto [self, args] = methodArguments(n);

        const std::string& k = args[0];

        if ( auto default_ = optionalArgument(args, 1); ! default_.empty() )
            result = fmt(
                "[](auto&& m, auto&& k, auto&& default_) { return m.contains(k) ? m.get(k) : default_; }(%s, %s, %s)",
                self, k, default_);
        else
            result = fmt("%s.get(%s)", self, k);
    }

    void operator()(operator_::map::GetOptional* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.get_optional(%s)", self, args[0]);
    }

    void operator()(operator_::map::IndexAssign* n) final {
        const auto& map = op0(n);
        const auto& key = op1(n);
        const auto& value = op2(n);
        result = fmt("%s.index_assign(%s, %s)", map, key, value);
    }

    void operator()(operator_::map::Clear* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.clear()", self);
    }

    /// Network

    void operator()(operator_::network::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::network::Unequal* n) final { result = binary(n, "!="); }
    void operator()(operator_::network::Family* n) final { result = fmt("%s.family()", op0(n)); }
    void operator()(operator_::network::Prefix* n) final { result = fmt("%s.prefix()", op0(n)); }
    void operator()(operator_::network::Length* n) final { result = fmt("%s.length()", op0(n)); }
    void operator()(operator_::network::In* n) final { result = fmt("%s.contains(%s)", op1(n), op0(n)); }

    /// Real

    void operator()(operator_::real::CastToInterval* n) final {
        result = fmt("::hilti::rt::Interval(%f, ::hilti::rt::Interval::SecondTag())", op0(n));
    }
    void operator()(operator_::real::CastToTime* n) final {
        result = fmt("::hilti::rt::Time(%f, ::hilti::rt::Time::SecondTag())", op0(n));
    }
    void operator()(operator_::real::Difference* n) final { result = binary(n, "-"); }
    void operator()(operator_::real::DifferenceAssign* n) final { result = binary(n, "-="); }
    void operator()(operator_::real::Division* n) final { result = binary(n, "/"); }
    void operator()(operator_::real::DivisionAssign* n) final { result = binary(n, "/="); }
    void operator()(operator_::real::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::real::Greater* n) final { result = binary(n, ">"); }
    void operator()(operator_::real::GreaterEqual* n) final { result = binary(n, ">="); }
    void operator()(operator_::real::Lower* n) final { result = binary(n, "<"); }
    void operator()(operator_::real::LowerEqual* n) final { result = binary(n, "<="); }
    void operator()(operator_::real::Modulo* n) final { result = fmt("std::fmod(%s,%s)", op0(n), op1(n)); }
    void operator()(operator_::real::Multiple* n) final { result = binary(n, "*"); }
    void operator()(operator_::real::MultipleAssign* n) final { result = binary(n, "*="); }
    void operator()(operator_::real::Power* n) final { result = fmt("std::pow(%s, %s)", op0(n), op1(n)); }
    void operator()(operator_::real::SignNeg* n) final { result = fmt("(-%s)", op0(n)); }
    void operator()(operator_::real::Sum* n) final { result = binary(n, "+"); }
    void operator()(operator_::real::SumAssign* n) final { result = binary(n, "+="); }
    void operator()(operator_::real::Unequal* n) final { result = binary(n, "!="); }

    void operator()(operator_::real::CastToSignedInteger* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::real::CastToUnsignedInteger* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    /// Result
    void operator()(operator_::error::Description* n) final { result = fmt("%s.description()", op0(n)); }

    void operator()(operator_::result::Deref* n) final { result = fmt("%s.valueOrThrow()", op0(n)); }

    void operator()(operator_::result::Error* n) final { result = fmt("%s.errorOrThrow()", op0(n)); }

    void operator()(operator_::generic::Pack* n) final {
        const auto& ctor = n->op0()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();
        const auto& type = ctor[0]->type();
        auto args = tupleArguments(n, n->op0());
        result = cg->pack(type, args[0], util::toVector(util::slice(args, 1, -1)));
    }

    void operator()(operator_::generic::Unpack* n) final {
        auto args = tupleArguments(n, n->op1());
        auto throw_on_error = n->op2()->as<expression::Ctor>()->ctor()->as<ctor::Bool>()->value();
        result = cg->unpack(n->op0()->type()->type()->as<type::Type_>()->typeValue(), tupleArgumentType(n->op1(), 0),
                            args[0], util::toVector(util::slice(args, 1, -1)), throw_on_error);
    }

    void operator()(operator_::generic::Begin* n) final {
        if ( n->op0()->type()->type()->iteratorType()->type()->dereferencedType()->isConstant() )
            result = fmt("%s.cbegin()", op0(n));
        else
            result = fmt("%s.begin()", op0(n));
    }

    void operator()(operator_::generic::End* n) final {
        if ( n->op0()->type()->type()->iteratorType()->type()->dereferencedType()->isConstant() )
            result = fmt("%s.cend()", op0(n));
        else
            result = fmt("%s.end()", op0(n));
    }

    void operator()(operator_::generic::New* n) final {
        auto* t = n->op0()->type()->type();

        if ( auto* tv = t->tryAs<type::Type_>() ) {
            auto* ctor = n->op1()->as<expression::Ctor>()->ctor();

            if ( auto* x = ctor->tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            std::string args;

            if ( ctor->as<ctor::Tuple>()->value().size() )
                args = util::join(cg->compileCallArguments(ctor->as<ctor::Tuple>()->value(),
                                                           tv->typeValue()->type()->parameters(),
                                                           hilti::detail::CodeGen::CtorKind::Parameters),
                                  ", ");
            else if ( auto def = cg->typeDefaultValue(tv->typeValue()) )
                args = *def;

            result = fmt("::hilti::rt::reference::make_strong<%s>(%s)",
                         cg->compile(tv->typeValue(), codegen::TypeUsage::Ctor), args);
        }
        else
            result = fmt("::hilti::rt::reference::make_strong<%s>(%s)",
                         cg->compile(n->op0()->type(), codegen::TypeUsage::Ctor), op0(n));
    }

    void operator()(operator_::generic::CastedCoercion* n) final {
        result = cg->coerce(cg->compile(n->op0()), n->op0()->type(), n->result());
    }

    void operator()(operator_::regexp::Match* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.match(%s)", self, args[0]);
    }

    void operator()(operator_::regexp::MatchGroups* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.matchGroups(%s)", self, args[0]);
    }

    void operator()(operator_::regexp::Find* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.find(%s)", self, args[0]);
    }

    void operator()(operator_::regexp::TokenMatcher* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.tokenMatcher()", self);
    }

    void operator()(operator_::regexp_match_state::AdvanceBytes* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.advance(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::regexp_match_state::AdvanceView* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.advance(%s)", self, args[0]);
    }

    // Optional
    void operator()(operator_::optional::Deref* n) final { result = {fmt("%s.value()", op0(n)), Side::LHS}; }

    /// Port

    void operator()(operator_::port::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::port::Unequal* n) final { result = binary(n, "!="); }

    void operator()(operator_::port::Ctor* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Port(%s, %s)", args[0], args[1]);
    }

    void operator()(operator_::port::Protocol* n) final { result = fmt("%s.protocol()", op0(n)); }

    // Set
    void operator()(operator_::set::iterator::IncrPostfix* n) final { result = fmt("%s++", op0(n)); }
    void operator()(operator_::set::iterator::IncrPrefix* n) final { result = fmt("++%s", op0(n)); }
    void operator()(operator_::set::iterator::Deref* n) final { result = {fmt("*%s", op0(n)), Side::LHS}; }
    void operator()(operator_::set::iterator::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::set::iterator::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::set::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::set::In* n) final { result = fmt("%s.contains(%s)", op1(n), op0(n)); }
    void operator()(operator_::set::Add* n) final { result = fmt("%s.insert(%s)", op0(n), op1(n)); }
    void operator()(operator_::set::Delete* n) final { result = fmt("%s.erase(%s)", op0(n), op1(n)); }
    void operator()(operator_::set::Size* n) final { result = fmt("%s.size()", op0(n)); }
    void operator()(operator_::set::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::set::Clear* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.clear()", self);
    }

    /// stream::Iterator

    void operator()(operator_::stream::iterator::Deref* n) final { result = {fmt("*%s", op0(n)), Side::LHS}; }
    void operator()(operator_::stream::iterator::IncrPostfix* n) final { result = fmt("%s++", op0(n)); }
    void operator()(operator_::stream::iterator::IncrPrefix* n) final { result = fmt("++%s", op0(n)); }
    void operator()(operator_::stream::iterator::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::stream::iterator::Lower* n) final { result = fmt("%s < %s", op0(n), op1(n)); }
    void operator()(operator_::stream::iterator::LowerEqual* n) final { result = fmt("%s <= %s", op0(n), op1(n)); }
    void operator()(operator_::stream::iterator::Greater* n) final { result = fmt("%s > %s", op0(n), op1(n)); }
    void operator()(operator_::stream::iterator::GreaterEqual* n) final { result = fmt("%s >= %s", op0(n), op1(n)); }
    void operator()(operator_::stream::iterator::Difference* n) final { result = fmt("%s - %s", op0(n), op1(n)); }
    void operator()(operator_::stream::iterator::Sum* n) final { result = fmt("%s + %s", op0(n), op1(n)); }
    void operator()(operator_::stream::iterator::SumAssign* n) final { result = fmt("%s += %s", op0(n), op1(n)); }
    void operator()(operator_::stream::iterator::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::stream::iterator::Offset* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.offset()", self);
    }

    void operator()(operator_::stream::iterator::IsFrozen* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.isFrozen()", self);
    }

    /// stream::View

    void operator()(operator_::stream::view::Size* n) final { result = fmt("%s.size()", op0(n)); }
    void operator()(operator_::stream::view::EqualView* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::stream::view::EqualBytes* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::stream::view::UnequalView* n) final { result = fmt("%s != %s", op0(n), op1(n)); }
    void operator()(operator_::stream::view::UnequalBytes* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::stream::view::Offset* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.offset()", self);
    }

    void operator()(operator_::stream::view::InBytes* n) final {
        result = fmt("::hilti::rt::tuple::get<0>(%s.find(%s))", op1(n), op0(n));
    }
    void operator()(operator_::stream::view::InView* n) final {
        result = fmt("::hilti::rt::tuple::get<0>(%s.find(%s))", op1(n), op0(n));
    }

    void operator()(operator_::stream::view::AdvanceTo* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.advance(%s)", self, args[0]);
    }

    void operator()(operator_::stream::view::AdvanceBy* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.advance(%s)", self, args[0]);
    }

    void operator()(operator_::stream::view::AdvanceToNextData* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.advanceToNextData()", self);
    }

    void operator()(operator_::stream::view::Limit* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.limit(%s)", self, args[0]);
    }

    void operator()(operator_::stream::view::Find* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.find(%s)", self, args[0]);
    }


    void operator()(operator_::stream::view::At* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.at(%s)", self, args[0]);
    }

    void operator()(operator_::stream::view::StartsWith* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.startsWith(%s)", self, args[0]);
    }

    void operator()(operator_::stream::view::SubIterators* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::stream::view::SubIterator* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.sub(%s)", self, args[0]);
    }

    void operator()(operator_::stream::view::SubOffsets* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }


    // Stream

    void operator()(operator_::stream::Size* n) final { result = fmt("%s.size()", op0(n)); }
    void operator()(operator_::stream::SumAssignView* n) final { result = fmt("%s.append(%s)", op0(n), op1(n)); }
    void operator()(operator_::stream::SumAssignBytes* n) final { result = fmt("%s.append(%s)", op0(n), op1(n)); }

    void operator()(operator_::stream::Ctor* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Stream(%s)", args[0]);
    }

    void operator()(operator_::stream::Freeze* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.freeze()", self);
    }

    void operator()(operator_::stream::Unfreeze* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.unfreeze()", self);
    }

    void operator()(operator_::stream::IsFrozen* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.isFrozen()", self);
    }

    void operator()(operator_::stream::At* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.at(%s)", self, args[0]);
    }

    void operator()(operator_::stream::Statistics* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.statistics()", self);
    }

    void operator()(operator_::stream::Trim* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.trim(%s)", self, args[0]);
    }

    // String

    void operator()(operator_::string::Sum* n) final { result = binary(n, "+"); }
    void operator()(operator_::string::SumAssign* n) final { result = binary(n, "+="); }
    void operator()(operator_::string::Size* n) final { result = fmt("::hilti::rt::string::size(%s)", op0(n)); }
    void operator()(operator_::string::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::string::Unequal* n) final { result = binary(n, "!="); }

    void operator()(operator_::string::Encode* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("::hilti::rt::string::encode(%s, %s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::string::Modulo* n) final {
        if ( n->op1()->type()->type()->isA<type::Tuple>() ) {
            if ( auto* ctor = n->op1()->tryAs<expression::Ctor>() ) {
                auto t = ctor->ctor()->as<ctor::Tuple>()->value();
                result = fmt("::hilti::rt::fmt(%s, %s)", op0(n),
                             util::join(t | std::views::transform([this](auto x) { return cg->compile(x); }), ", "));
                return;
            }
        }

        result = fmt("::hilti::rt::fmt(%s, %s)", op0(n), op1(n));
    }

    void operator()(operator_::string::Split* n) final {
        auto [self, args] = methodArguments(n);
        std::string sep;

        if ( auto x = optionalArgument(args, 0); ! x.empty() )
            sep = fmt(", %s", x);

        result = fmt("::hilti::rt::string::split(%s%s)", self, sep);
    }

    void operator()(operator_::string::Split1* n) final {
        auto [self, args] = methodArguments(n);
        std::string sep;

        if ( auto x = optionalArgument(args, 0); ! x.empty() )
            sep = fmt(", %s", x);

        result = fmt("::hilti::rt::string::split1(%s%s)", self, sep);
    }

    void operator()(operator_::string::StartsWith* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("::hilti::rt::startsWith(%s, %s)", self, args[0]);
    }

    void operator()(operator_::string::EndsWith* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("::hilti::rt::endsWith(%s, %s)", self, args[0]);
    }

    void operator()(operator_::string::LowerCase* n) final { result = fmt("::hilti::rt::string::lower(%s)", op0(n)); }

    void operator()(operator_::string::UpperCase* n) final { result = fmt("::hilti::rt::string::upper(%s)", op0(n)); }

    // Strong reference
    void operator()(operator_::strong_reference::Deref* n) final { result = {fmt("(*%s)", op0(n)), Side::LHS}; }
    void operator()(operator_::strong_reference::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::strong_reference::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    /// Struct

    auto memberAccess(const expression::ResolvedOperator* o, const std::string& self, const std::string& member) {
        return fmt("%s.%s", self, cxx::ID(member));
    }

    auto memberAccess(const expression::ResolvedOperator* o, const std::string& member, bool lhs = false) {
        return memberAccess(o, cg->compile(o->op0()), member);
    }

    cxx::Expression structMember(const expression::ResolvedOperator* o) {
        const auto& op0 = o->op0();
        const auto& id = o->op1()->as<expression::Member>()->id();
        auto attr = memberAccess(o, id);

        auto* type = op0->type()->type();
        if ( type->isReferenceType() )
            type = type->dereferencedType()->type();

        if ( auto* f = type->as<type::Struct>()->field(id); f->isOptional() ) {
            auto* d = f->default_();

            if ( lhs ) {
                if ( d )
                    return {fmt("%s.valueOrInit(%s)", attr, cg->compile(d)), Side::LHS};

                return {fmt("%s.valueOrInit()", attr), Side::LHS};
            }

            if ( d )
                return fmt("%s.valueOr(%s)", attr, cg->compile(d));

            return fmt("%s.value()", attr);
        }

        return {std::move(attr), Side::LHS};
    }

    void operator()(operator_::struct_::MemberConst* n) final { result = structMember(n); }
    void operator()(operator_::struct_::MemberNonConst* n) final { result = structMember(n); }

    void operator()(operator_::struct_::MemberCall* n) final {
        const auto& op = static_cast<const struct_::MemberCall&>(n->operator_());
        auto* fdecl = op.declaration();
        assert(fdecl);

        auto* ft = fdecl->type()->type()->as<type::Function>();
        auto args = n->op2()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();
        const auto& id = n->op1()->as<expression::Member>()->id();

        assert(args.size() == ft->parameters().size());
        std::vector<std::pair<Expression*, bool>> zipped;

        zipped.reserve(args.size());
        for ( auto i = 0U; i < args.size(); i++ )
            zipped.emplace_back(args[i], ft->parameters()[i]->kind() == parameter::Kind::InOut);

        result = memberAccess(n,
                              fmt("%s(%s)", id,
                                  util::join(zipped | std::views::transform([this](const auto& x) {
                                                 return cg->compile(x.first, x.second);
                                             }),
                                             ", ")),
                              false);
    }

    void operator()(operator_::struct_::HasMember* n) final {
        const auto& id = n->op1()->as<expression::Member>()->id();

        auto* type = n->op0()->type()->type();
        if ( type->isReferenceType() )
            type = type->dereferencedType()->type();

        if ( auto* f = type->as<type::Struct>()->field(id); f->isOptional() )
            result = fmt("%s.hasValue()", memberAccess(n, id));
        else
            result = "true";
    }

    void operator()(operator_::struct_::TryMember* n) final {
        const auto& id = n->op1()->as<expression::Member>()->id();
        assert(! lhs);

        auto* type = n->op0()->type()->type();
        if ( type->isReferenceType() )
            type = type->dereferencedType()->type();

        if ( auto* f = type->as<type::Struct>()->field(id); f->isOptional() ) {
            auto attr = memberAccess(n, id);

            if ( auto* d = f->default_() )
                result = memberAccess(n, fmt("value_or(%s)", cg->compile(d)));
            else
                result = fmt("::hilti::rt::struct_::value_or_exception(%s)", attr);
        }
        else
            result = structMember(n);
    }

    void operator()(operator_::struct_::Unset* n) final {
        auto id = n->op1()->as<expression::Member>()->id();
        result = fmt("%s.reset()", memberAccess(n, std::move(id)));
    }

    /// Union

    unsigned int unionFieldIndex(Expression* op0, Expression* op1) {
        const auto& id = op1->as<expression::Member>()->id();
        return op0->type()->type()->as<type::Union>()->index(id);
    }

    void operator()(operator_::union_::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::union_::Unequal* n) final { result = binary(n, "!="); }

    void operator()(operator_::union_::MemberConst* n) final {
        auto idx = unionFieldIndex(n->op0(), n->op1());
        result = {fmt("::hilti::rt::union_::get<%u>(%s)", idx, op0(n)), Side::LHS};
    }

    void operator()(operator_::union_::MemberNonConst* n) final {
        auto idx = unionFieldIndex(n->op0(), n->op1());

        if ( lhs )
            result = {fmt("::hilti::rt::union_::get_proxy<%u>(%s)", idx, op0(n)), Side::LHS};
        else
            result = fmt("::hilti::rt::union_::get<%u>(%s)", idx, op0(n));
    }

    void operator()(operator_::union_::HasMember* n) final {
        auto idx = unionFieldIndex(n->op0(), n->op1());
        result = fmt("(%s.index() == %u)", op0(n), idx);
    }

    // Signed integer

    void operator()(operator_::signed_integer::CastToBool* n) final { result = fmt("::hilti::rt::Bool(%s)", op0(n)); }
    void operator()(operator_::signed_integer::CastToInterval* n) final {
        result = fmt("::hilti::rt::Interval(::hilti::rt::integer::safe<int64_t>(%" PRId64
                     ") * 1000000000, ::hilti::rt::Interval::NanosecondTag())",
                     op0(n));
    }
    void operator()(operator_::signed_integer::CastToEnum* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("::hilti::rt::enum_::from_int<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }
    void operator()(operator_::signed_integer::DecrPostfix* n) final { result = fmt("%s--", op0(n)); }
    void operator()(operator_::signed_integer::DecrPrefix* n) final { result = fmt("--%s", op0(n)); }
    void operator()(operator_::signed_integer::Difference* n) final { result = fmt("%s - %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::DifferenceAssign* n) final { result = fmt("%s -= %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::Division* n) final { result = fmt("%s / %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::DivisionAssign* n) final { result = fmt("%s /= %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::Greater* n) final { result = fmt("%s > %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::GreaterEqual* n) final { result = fmt("%s >= %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::IncrPostfix* n) final { result = fmt("%s++", op0(n)); }
    void operator()(operator_::signed_integer::IncrPrefix* n) final { result = fmt("++%s", op0(n)); }
    void operator()(operator_::signed_integer::Lower* n) final { result = fmt("%s < %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::LowerEqual* n) final { result = fmt("%s <= %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::Modulo* n) final { result = fmt("%s %% %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::Multiple* n) final { result = fmt("%s * %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::MultipleAssign* n) final { result = fmt("%s *= %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::Power* n) final {
        result = fmt("::hilti::rt::pow(%s, %s)", op0(n), op1(n));
    }
    void operator()(operator_::signed_integer::SignNeg* n) final { result = fmt("(-%s)", op0(n)); }
    void operator()(operator_::signed_integer::Sum* n) final { result = fmt("%s + %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::SumAssign* n) final { result = fmt("%s += %s", op0(n), op1(n)); }
    void operator()(operator_::signed_integer::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::signed_integer::CastToSigned* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::signed_integer::CastToUnsigned* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::signed_integer::CastToReal* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::signed_integer::CtorSigned8* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<int8_t>(%s)", args[0]);
    }

    void operator()(operator_::signed_integer::CtorSigned16* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<int16_t>(%s)", args[0]);
    }

    void operator()(operator_::signed_integer::CtorSigned32* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<int32_t>(%s)", args[0]);
    }

    void operator()(operator_::signed_integer::CtorSigned64* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<int64_t>(%s)", args[0]);
    }

    void operator()(operator_::signed_integer::CtorUnsigned8* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<int8_t>(%s)", args[0]);
    }

    void operator()(operator_::signed_integer::CtorUnsigned16* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<int16_t>(%s)", args[0]);
    }

    void operator()(operator_::signed_integer::CtorUnsigned32* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<int32_t>(%s)", args[0]);
    }

    void operator()(operator_::signed_integer::CtorUnsigned64* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<int64_t>(%s)", args[0]);
    }

    // Time

    void operator()(operator_::time::DifferenceInterval* n) final { result = binary(n, "-"); }
    void operator()(operator_::time::DifferenceTime* n) final { result = binary(n, "-"); }
    void operator()(operator_::time::Equal* n) final { result = binary(n, "=="); }
    void operator()(operator_::time::Greater* n) final { result = binary(n, ">"); }
    void operator()(operator_::time::GreaterEqual* n) final { result = binary(n, ">="); }
    void operator()(operator_::time::Lower* n) final { result = binary(n, "<"); }
    void operator()(operator_::time::LowerEqual* n) final { result = binary(n, "<="); }
    void operator()(operator_::time::Nanoseconds* n) final { result = fmt("%s.nanoseconds()", op0(n)); }
    void operator()(operator_::time::Seconds* n) final { result = fmt("%s.seconds()", op0(n)); }
    void operator()(operator_::time::SumInterval* n) final { result = binary(n, "+"); }
    void operator()(operator_::time::Unequal* n) final { result = binary(n, "!="); }

    void operator()(operator_::time::CtorSignedIntegerSecs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Time(%s, ::hilti::rt::Time::SecondTag())", args[0]);
    }

    void operator()(operator_::time::CtorSignedIntegerNs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Time(%s, ::hilti::rt::Time::NanosecondTag())", args[0]);
    }

    void operator()(operator_::time::CtorUnsignedIntegerSecs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Time(%s, ::hilti::rt::Time::SecondTag())", args[0]);
    }

    void operator()(operator_::time::CtorUnsignedIntegerNs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Time(%s, ::hilti::rt::Time::NanosecondTag())", args[0]);
    }

    void operator()(operator_::time::CtorRealSecs* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("::hilti::rt::Time(%f, ::hilti::rt::Time::SecondTag())", args[0]);
    }

    // Tuple

    void operator()(operator_::tuple::CustomAssign* n) final {
        auto t = n->operands()[0]->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();
        auto l = util::join(t | std::views::transform([this](auto x) { return cg->compile(x, true); }), ", ");
        result = {fmt("::hilti::rt::tuple::assign(std::tie(%s), %s)", l, op1(n)), Side::LHS};
    }

    void operator()(operator_::tuple::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::tuple::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::tuple::Index* n) final {
        auto i = n->op1()->as<expression::Ctor>()->ctor()->as<ctor::UnsignedInteger>()->value();
        result = {fmt("::hilti::rt::tuple::get<%u>(%s)", i, op0(n)), Side::LHS};
    }

    void operator()(operator_::tuple::Member* n) final {
        const auto& id = n->op1()->as<expression::Member>()->id();
        auto elem = n->op0()->type()->type()->as<type::Tuple>()->elementByID(id);
        assert(elem);
        result = {fmt("::hilti::rt::tuple::get<%u>(%s)", elem->first, op0(n)), Side::LHS};
    }

    // Unsigned integer

    void operator()(operator_::unsigned_integer::BitAnd* n) final { result = fmt("(%s & %s)", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::BitOr* n) final { result = fmt("(%s | %s)", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::BitXor* n) final { result = fmt("(%s ^ %s)", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::CastToBool* n) final { result = fmt("::hilti::rt::Bool(%s)", op0(n)); }
    void operator()(operator_::unsigned_integer::CastToEnum* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("::hilti::rt::enum_::from_uint<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }
    void operator()(operator_::unsigned_integer::CastToInterval* n) final {
        result = fmt("::hilti::rt::Interval(::hilti::rt::integer::safe<uint64_t>(%" PRIu64
                     ") * 1000000000, ::hilti::rt::Interval::NanosecondTag())",
                     op0(n));
    }
    void operator()(operator_::unsigned_integer::CastToTime* n) final {
        result = fmt("::hilti::rt::Time(::hilti::rt::integer::safe<uint64_t>(%" PRIu64
                     ") * 1'000'000'000, ::hilti::rt::Time::NanosecondTag())",
                     op0(n));
    }
    void operator()(operator_::unsigned_integer::DecrPostfix* n) final { result = fmt("%s--", op0(n)); }
    void operator()(operator_::unsigned_integer::DecrPrefix* n) final { result = fmt("--%s", op0(n)); }
    void operator()(operator_::unsigned_integer::Difference* n) final { result = fmt("%s - %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::DifferenceAssign* n) final {
        result = fmt("%s -= %s", op0(n), op1(n));
    }
    void operator()(operator_::unsigned_integer::Division* n) final { result = fmt("%s / %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::DivisionAssign* n) final { result = fmt("%s /= %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::Greater* n) final { result = fmt("%s > %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::GreaterEqual* n) final { result = fmt("%s >= %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::IncrPostfix* n) final { result = fmt("%s++", op0(n)); }
    void operator()(operator_::unsigned_integer::IncrPrefix* n) final { result = fmt("++%s", op0(n)); }
    void operator()(operator_::unsigned_integer::Lower* n) final { result = fmt("%s < %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::LowerEqual* n) final { result = fmt("%s <= %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::Modulo* n) final { result = fmt("%s %% %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::Multiple* n) final { result = fmt("%s * %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::MultipleAssign* n) final { result = fmt("%s *= %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::Negate* n) final { result = fmt("~%s", op0(n)); }
    void operator()(operator_::unsigned_integer::Power* n) final {
        result = fmt("::hilti::rt::pow(%s, %s)", op0(n), op1(n));
    }
    void operator()(operator_::unsigned_integer::ShiftLeft* n) final { result = fmt("(%s << %s)", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::ShiftRight* n) final { result = fmt("(%s >> %s)", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::SignNeg* n) final { result = fmt("(-%s)", op0(n)); }
    void operator()(operator_::unsigned_integer::Sum* n) final { result = fmt("%s + %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::SumAssign* n) final { result = fmt("%s += %s", op0(n), op1(n)); }
    void operator()(operator_::unsigned_integer::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::unsigned_integer::CastToSigned* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::unsigned_integer::CastToUnsigned* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::unsigned_integer::CastToReal* n) final {
        auto* t = n->op1()->type()->type()->as<type::Type_>()->typeValue();
        result = fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    void operator()(operator_::unsigned_integer::CtorSigned8* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<uint8_t>(%s)", args[0]);
    }

    void operator()(operator_::unsigned_integer::CtorSigned16* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<uint16_t>(%s)", args[0]);
    }

    void operator()(operator_::unsigned_integer::CtorSigned32* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<uint32_t>(%s)", args[0]);
    }

    void operator()(operator_::unsigned_integer::CtorSigned64* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<uint64_t>(%s)", args[0]);
    }

    void operator()(operator_::unsigned_integer::CtorUnsigned8* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<uint8_t>(%s)", args[0]);
    }

    void operator()(operator_::unsigned_integer::CtorUnsigned16* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<uint16_t>(%s)", args[0]);
    }

    void operator()(operator_::unsigned_integer::CtorUnsigned32* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<uint32_t>(%s)", args[0]);
    }

    void operator()(operator_::unsigned_integer::CtorUnsigned64* n) final {
        auto args = tupleArguments(n, n->op1());
        result = fmt("static_cast<uint64_t>(%s)", args[0]);
    }

    // Vector
    void operator()(operator_::vector::iterator::IncrPostfix* n) final { result = fmt("%s++", op0(n)); }
    void operator()(operator_::vector::iterator::IncrPrefix* n) final { result = fmt("++%s", op0(n)); }
    void operator()(operator_::vector::iterator::Deref* n) final { result = {fmt("*%s", op0(n)), Side::LHS}; }
    void operator()(operator_::vector::iterator::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::vector::iterator::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    void operator()(operator_::vector::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::vector::IndexConst* n) final { result = {fmt("%s[%s]", op0(n), op1(n)), Side::LHS}; }
    void operator()(operator_::vector::IndexNonConst* n) final { result = {fmt("%s[%s]", op0(n), op1(n)), Side::LHS}; }
    void operator()(operator_::vector::Size* n) final { result = fmt("%s.size()", op0(n)); }
    void operator()(operator_::vector::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }
    void operator()(operator_::vector::Sum* n) final { result = fmt("%s + %s", op0(n), op1(n)); }
    void operator()(operator_::vector::SumAssign* n) final { result = fmt("%s += %s", op0(n), op1(n)); }

    void operator()(operator_::vector::Back* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.back()", self);
    }

    void operator()(operator_::vector::Front* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.front()", self);
    }

    void operator()(operator_::vector::Assign* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.assign(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::vector::PushBack* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.emplace_back(%s)", self, args[0]);
    }

    void operator()(operator_::vector::PopBack* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.pop_back()", self);
    }

    void operator()(operator_::vector::Reserve* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.reserve(%s)", self, args[0]);
    }

    void operator()(operator_::vector::Resize* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.resize(%s)", self, args[0]);
    }

    void operator()(operator_::vector::At* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.iteratorAt(%s)", self, args[0]);
    }

    void operator()(operator_::vector::SubRange* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }

    void operator()(operator_::vector::SubEnd* n) final {
        auto [self, args] = methodArguments(n);
        result = fmt("%s.sub(%s)", self, args[0]);
    }

    // Weak reference
    void operator()(operator_::weak_reference::Deref* n) final { result = {fmt("(*%s)", op0(n)), Side::LHS}; }
    void operator()(operator_::weak_reference::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::weak_reference::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }

    // Value reference
    void operator()(operator_::value_reference::Deref* n) final { result = {fmt("(*%s)", op0(n)), Side::LHS}; }
    void operator()(operator_::value_reference::Equal* n) final { result = fmt("%s == %s", op0(n), op1(n)); }
    void operator()(operator_::value_reference::Unequal* n) final { result = fmt("%s != %s", op0(n), op1(n)); }
};

} // anonymous namespace

cxx::Expression CodeGen::compile(expression::ResolvedOperator* o, bool lhs) {
    auto v = Visitor(this, lhs);
    if ( auto x = hilti::visitor::dispatch(v, o, [](const auto& v) -> const auto& { return v.result; }) )
        return lhs ? _makeLhs(*x, o->type()) : *x;

    std::cerr << o->dump();
    logger().internalError(fmt("operator failed to compile: %s (%s)", o->printSignature(), o->typename_()));
}
