// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/operators/all.h>
#include <hilti/base/logger.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>
#include <hilti/compiler/detail/visitors.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : hilti::visitor::PreOrder<cxx::Expression, Visitor> {
    Visitor(CodeGen* cg, bool lhs) : cg(cg), lhs(lhs) {}
    CodeGen* cg;
    bool lhs;

    // Helpers

    result_t op0(const expression::ResolvedOperatorBase& o, bool lhs = false) { return cg->compile(o.op0(), lhs); }

    result_t op1(const expression::ResolvedOperatorBase& o, bool lhs = false) { return cg->compile(o.op1(), lhs); }

    result_t op2(const expression::ResolvedOperatorBase& o, bool lhs = false) { return cg->compile(o.op2(), lhs); }

    result_t binary(const expression::ResolvedOperatorBase& o, const std::string& x) {
        return fmt("%s %s %s", op0(o), x, op1(o));
    }

    auto compileExpressions(const std::vector<Expression>& exprs) {
        return util::transform(exprs, [&](const auto& e) { return cg->compile(e); });
    }

    auto compileExpressions(const node::Range<Expression>& exprs) {
        return node::transform(exprs, [&](const auto& e) { return cg->compile(e); });
    }

    auto tupleArguments(const expression::ResolvedOperatorBase& o, const Expression& op) {
        auto ctor = op.as<expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return compileExpressions(ctor.as<ctor::Tuple>().value());
    }

    auto methodArguments(const expression::ResolvedOperatorBase& o) {
        auto ops = o.op2();

        // If the argument list was the result of a coercion unpack its result.
        if ( auto coerced = ops.tryAs<expression::Coerced>() )
            ops = coerced->expression();

        if ( auto ctor_ = ops.tryAs<expression::Ctor>() ) {
            auto ctor = ctor_->ctor();

            // If the argument was the result of a coercion unpack its result.
            if ( auto x = ctor.tryAs<ctor::Coerced>() )
                ctor = x->coercedCtor();

            if ( auto args = ctor.tryAs<ctor::Tuple>() )
                return std::make_pair(op0(o), compileExpressions(args->value()));
        }

        util::cannot_be_reached();
    }

    auto optionalArgument(const std::vector<cxx::Expression>& args, unsigned int i) {
        return i < args.size() ? std::string(args[i]) : "";
    }

    std::optional<cxx::Expression> optionalArgument(const std::vector<Expression>& args, unsigned int i) {
        if ( i < args.size() )
            return cg->compile(args[i], false);

        return {};
    }

    /// Address

    result_t operator()(const operator_::address::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::address::Unequal& n) { return binary(n, "!="); }
    result_t operator()(const operator_::address::Family& n) { return fmt("%s.family()", op0(n)); }

    /// Bool

    result_t operator()(const operator_::bool_::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::bool_::Unequal& n) { return binary(n, "!="); }

    /// bytes::Iterator

    result_t operator()(const operator_::bytes::iterator::Deref& n) { return {fmt("*%s", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::bytes::iterator::IncrPostfix& n) { return fmt("%s++", op0(n)); }
    result_t operator()(const operator_::bytes::iterator::IncrPrefix& n) { return fmt("++%s", op0(n)); }
    result_t operator()(const operator_::bytes::iterator::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::iterator::Lower& n) { return fmt("%s < %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::iterator::LowerEqual& n) { return fmt("%s <= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::iterator::Greater& n) { return fmt("%s > %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::iterator::GreaterEqual& n) { return fmt("%s >= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::iterator::Difference& n) { return fmt("%s - %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::iterator::Sum& n) { return fmt("%s + %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::iterator::SumAssign& n) { return fmt("%s += %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::iterator::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    // Bytes

    result_t operator()(const operator_::bytes::Size& n) { return fmt("%s.size()", op0(n)); }
    result_t operator()(const operator_::bytes::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::Lower& n) { return fmt("%s < %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::LowerEqual& n) { return fmt("%s <= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::Greater& n) { return fmt("%s > %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::GreaterEqual& n) { return fmt("%s >= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::Sum& n) { return fmt("%s + %s", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::SumAssignBytes& n) { return fmt("%s.append(%s)", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::SumAssignStreamView& n) { return fmt("%s.append(%s)", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::SumAssignUInt8& n) { return fmt("%s.append(%s)", op0(n), op1(n)); }
    result_t operator()(const operator_::bytes::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::bytes::In& n) { return fmt("std::get<0>(%s.find(%s))", op1(n), op0(n)); }

    result_t operator()(const operator_::bytes::Find& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.find(%s)", self, args[0]);
    }

    result_t operator()(const operator_::bytes::LowerCase& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.lower(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::bytes::UpperCase& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.upper(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::bytes::At& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.at(%s)", self, args[0]);
    }

    result_t operator()(const operator_::bytes::Split& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.split(%s)", self, optionalArgument(args, 0));
    }

    result_t operator()(const operator_::bytes::Split1& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.split1(%s)", self, optionalArgument(args, 0));
    }

    result_t operator()(const operator_::bytes::StartsWith& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.startsWith(%s)", self, args[0]);
    }

    result_t operator()(const operator_::bytes::Strip& n) {
        auto [self, args] = methodArguments(n);

        std::string x;

        if ( auto side = optionalArgument(args, 1); ! side.empty() )
            x = side;

        if ( auto set = optionalArgument(args, 0); ! set.empty() ) {
            if ( x.size() )
                x += ", ";

            x += set;
        }

        return fmt("%s.strip(%s)", self, x);
    }

    result_t operator()(const operator_::bytes::SubIterators& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::bytes::SubIterator& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.sub(%s)", self, args[0]);
    }

    result_t operator()(const operator_::bytes::SubOffsets& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::bytes::Join& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.join(%s)", self, args[0]);
    }

    result_t operator()(const operator_::bytes::ToIntAscii& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.toInt(%s)", self, optionalArgument(args, 0));
    }

    result_t operator()(const operator_::bytes::ToUIntAscii& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.toUInt(%s)", self, optionalArgument(args, 0));
    }

    result_t operator()(const operator_::bytes::ToIntBinary& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.toInt(%s)", self, optionalArgument(args, 0));
    }

    result_t operator()(const operator_::bytes::ToUIntBinary& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.toUInt(%s)", self, optionalArgument(args, 0));
    }

    result_t operator()(const operator_::bytes::ToTimeAscii& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.toTime(%s)", self, optionalArgument(args, 0));
    }

    result_t operator()(const operator_::bytes::ToTimeBinary& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.toTime(%s)", self, optionalArgument(args, 0));
    }

    result_t operator()(const operator_::bytes::Decode& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.decode(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::bytes::Match& n) {
        auto [self, args] = methodArguments(n);

        std::string group;

        if ( auto x = optionalArgument(args, 1); ! x.empty() )
            group = fmt(", %s", x);

        return fmt("%s.match(%s%s)", self, args[0], group);
    }

    // Enum

    result_t operator()(const operator_::enum_::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::enum_::Unequal& n) { return binary(n, "!="); }

    result_t operator()(const operator_::enum_::CastToSignedInteger& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s.value())", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::enum_::CastToUnsignedInteger& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s.value())", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::enum_::CtorSigned& n) {
        auto args = tupleArguments(n, n.op1());
        auto t = n.op0().type().as<type::Type_>().typeValue();
        return fmt("%s{%s}", cg->compile(t, codegen::TypeUsage::Storage), args[0]);
    }

    result_t operator()(const operator_::enum_::CtorUnsigned& n) {
        auto args = tupleArguments(n, n.op1());
        auto t = n.op0().type().as<type::Type_>().typeValue();
        return fmt("%s{%s}", cg->compile(t, codegen::TypeUsage::Storage), args[0]);
    }

    result_t operator()(const operator_::enum_::HasLabel& n) {
        return fmt("::hilti::rt::enum_::has_label(%s, %s)", op0(n), cg->typeInfo(n.op0().type()));
    }

    // Error

    result_t operator()(const operator_::error::Ctor& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::result::Error(%s)", args[0]);
    }

    // Exception

    result_t operator()(const operator_::exception::Ctor& n) {
        std::string type;

        auto args = tupleArguments(n, n.op1());

        if ( auto x = n.op0().type().cxxID() )
            type = x->str();
        else
            type = cg->compile(n.op0().type().as<type::Type_>().typeValue(), codegen::TypeUsage::Ctor);

        return fmt("%s(%s)", type, args[0]);
    }

    result_t operator()(const operator_::exception::Description& n) { return fmt("%s.description()", op0(n)); }

    // Interval

    result_t operator()(const operator_::interval::Difference& n) { return binary(n, "-"); }
    result_t operator()(const operator_::interval::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::interval::Greater& n) { return binary(n, ">"); }
    result_t operator()(const operator_::interval::GreaterEqual& n) { return binary(n, ">="); }
    result_t operator()(const operator_::interval::Lower& n) { return binary(n, "<"); }
    result_t operator()(const operator_::interval::LowerEqual& n) { return binary(n, "<="); }
    result_t operator()(const operator_::interval::MultipleUnsignedInteger& n) { return binary(n, "*"); }
    result_t operator()(const operator_::interval::MultipleReal& n) { return binary(n, "*"); }
    result_t operator()(const operator_::interval::Nanoseconds& n) { return fmt("%s.nanoseconds()", op0(n)); }
    result_t operator()(const operator_::interval::Seconds& n) { return fmt("%s.seconds()", op0(n)); }
    result_t operator()(const operator_::interval::Sum& n) { return binary(n, "+"); }
    result_t operator()(const operator_::interval::Unequal& n) { return binary(n, "!="); }

    result_t operator()(const operator_::interval::CtorSignedIntegerSecs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Interval(%s, hilti::rt::Interval::SecondTag())", args[0]);
    }

    result_t operator()(const operator_::interval::CtorSignedIntegerNs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Interval(%s, hilti::rt::Interval::NanosecondTag())", args[0]);
    }

    result_t operator()(const operator_::interval::CtorUnsignedIntegerSecs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Interval(%s, hilti::rt::Interval::SecondTag())", args[0]);
    }

    result_t operator()(const operator_::interval::CtorUnsignedIntegerNs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Interval(%s, hilti::rt::Interval::NanosecondTag())", args[0]);
    }

    result_t operator()(const operator_::interval::CtorRealSecs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Interval(%f, hilti::rt::Interval::SecondTag())", args[0]);
    }

    // List
    result_t operator()(const operator_::list::iterator::IncrPostfix& n) { return fmt("%s++", op0(n)); }
    result_t operator()(const operator_::list::iterator::IncrPrefix& n) { return fmt("++%s", op0(n)); }
    result_t operator()(const operator_::list::iterator::Deref& n) { return {fmt("*%s", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::list::iterator::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::list::iterator::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::list::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::list::Size& n) { return fmt("%s.size()", op0(n)); }
    result_t operator()(const operator_::list::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    // Map

    result_t operator()(const operator_::map::iterator::IncrPostfix& n) { return fmt("%s++", op0(n)); }
    result_t operator()(const operator_::map::iterator::IncrPrefix& n) { return fmt("++%s", op0(n)); }
    result_t operator()(const operator_::map::iterator::Deref& n) { return {fmt("*%s", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::map::iterator::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::map::iterator::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::map::Delete& n) { return fmt("%s.erase(%s)", op0(n), op1(n)); }
    result_t operator()(const operator_::map::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::map::In& n) { return fmt("%s.contains(%s)", op1(n), op0(n)); }
    result_t operator()(const operator_::map::IndexConst& n) { return {fmt("%s[%s]", op0(n), op1(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::map::IndexNonConst& n) {
        return {fmt("%s[%s]", op0(n), op1(n)), cxx::Side::LHS};
    }
    result_t operator()(const operator_::map::Size& n) { return fmt("%s.size()", op0(n)); }
    result_t operator()(const operator_::map::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::map::Get& n) {
        auto [self, args] = methodArguments(n);

        const std::string& k = args[0];

        if ( auto default_ = optionalArgument(args, 1); ! default_.empty() )
            return fmt(
                "[](auto&& m, auto&& k, auto&& default_) { return m.contains(k)? m.get(k) : default_; }(%s, %s, %s)",
                self, k, default_);
        else
            return fmt("%s.get(%s)", self, k);
    }

    result_t operator()(const operator_::map::IndexAssign& n) {
        const auto& map = op0(n);
        const auto& key = op1(n);
        const auto& value = op2(n);
        return fmt("%s.index_assign(%s, %s)", map, key, value);
    }

    result_t operator()(const operator_::map::Clear& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.clear()", self);
    }

    /// Network

    result_t operator()(const operator_::network::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::network::Unequal& n) { return binary(n, "!="); }
    result_t operator()(const operator_::network::Family& n) { return fmt("%s.family()", op0(n)); }
    result_t operator()(const operator_::network::Prefix& n) { return fmt("%s.prefix()", op0(n)); }
    result_t operator()(const operator_::network::Length& n) { return fmt("%s.length()", op0(n)); }
    result_t operator()(const operator_::network::In& n) { return fmt("%s.contains(%s)", op1(n), op0(n)); }

    /// Real

    result_t operator()(const operator_::real::CastToInterval& n) {
        return fmt("::hilti::rt::Interval(%f, hilti::rt::Interval::SecondTag())", op0(n));
    }
    result_t operator()(const operator_::real::CastToTime& n) {
        return fmt("::hilti::rt::Time(%f, hilti::rt::Time::SecondTag())", op0(n));
    }
    result_t operator()(const operator_::real::Difference& n) { return binary(n, "-"); }
    result_t operator()(const operator_::real::DifferenceAssign& n) { return binary(n, "-="); }
    result_t operator()(const operator_::real::Division& n) { return binary(n, "/"); }
    result_t operator()(const operator_::real::DivisionAssign& n) { return binary(n, "/="); }
    result_t operator()(const operator_::real::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::real::Greater& n) { return binary(n, ">"); }
    result_t operator()(const operator_::real::GreaterEqual& n) { return binary(n, ">="); }
    result_t operator()(const operator_::real::Lower& n) { return binary(n, "<"); }
    result_t operator()(const operator_::real::LowerEqual& n) { return binary(n, "<="); }
    result_t operator()(const operator_::real::Modulo& n) { return fmt("std::fmod(%s,%s)", op0(n), op1(n)); }
    result_t operator()(const operator_::real::Multiple& n) { return binary(n, "*"); }
    result_t operator()(const operator_::real::MultipleAssign& n) { return binary(n, "*="); }
    result_t operator()(const operator_::real::Power& n) { return fmt("std::pow(%s, %s)", op0(n), op1(n)); }
    result_t operator()(const operator_::real::SignNeg& n) { return fmt("(-%s)", op0(n)); }
    result_t operator()(const operator_::real::Sum& n) { return binary(n, "+"); }
    result_t operator()(const operator_::real::SumAssign& n) { return binary(n, "+="); }
    result_t operator()(const operator_::real::Unequal& n) { return binary(n, "!="); }

    result_t operator()(const operator_::real::CastToSignedInteger& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::real::CastToUnsignedInteger& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    /// Result
    result_t operator()(const operator_::error::Description& n) { return fmt("%s.description()", op0(n)); }

    result_t operator()(const operator_::result::Deref& n) { return fmt("%s.valueOrThrow()", op0(n)); }

    result_t operator()(const operator_::result::Error& n) { return fmt("%s.errorOrThrow()", op0(n)); }

    result_t operator()(const operator_::generic::Pack& n) {
        const auto& ctor = n.op0().as<expression::Ctor>().ctor().as<ctor::Tuple>().value();
        const auto& type = ctor[0].type();
        auto args = tupleArguments(n, n.op0());
        return cg->pack(type, args[0], util::slice(args, 1, -1));
    }

    result_t operator()(const operator_::generic::Unpack& n) {
        auto args = tupleArguments(n, n.op1());
        auto throw_on_error = n.op2().as<expression::Ctor>().ctor().as<ctor::Bool>().value();
        return cg->unpack(n.op0().type().as<type::Type_>().typeValue(), args[0], util::slice(args, 1, -1),
                          throw_on_error);
    }

    result_t operator()(const operator_::generic::Begin& n) { return fmt("%s.begin()", op0(n)); }

    result_t operator()(const operator_::generic::End& n) { return fmt("%s.end()", op0(n)); }

    result_t operator()(const operator_::generic::New& n) {
        if ( auto tv = n.op0().type().tryAs<type::Type_>() ) {
            auto args = util::join(tupleArguments(n, n.op1()), ", ");
            return fmt("::hilti::rt::reference::make_strong<%s>(%s)",
                       cg->compile(tv->typeValue(), codegen::TypeUsage::Ctor), args);
        }
        else {
            return fmt("::hilti::rt::reference::make_strong<%s>(%s)",
                       cg->compile(n.op0().type(), codegen::TypeUsage::Ctor), op0(n));
        }
    }

    result_t operator()(const operator_::generic::CastedCoercion& n) {
        return cg->compile(expression::Coerced(n.op0(), n.result(), n.meta()));
    }

    result_t operator()(const operator_::function::Call& n) {
        // 1st operand directly references a function, validator ensures that.
        auto f = n.op0().as<expression::ResolvedID>().declaration().as<declaration::Function>();

        auto name = op0(n);

        if ( auto a = AttributeSet::find(f.function().attributes(), "&cxxname") ) {
            if ( auto s = a->valueAsString() )
                name = cxx::Expression(*s);
            else
                logger().error(s, n);
        }

        const auto& values = n.op1().as<expression::Ctor>().ctor().as<ctor::Tuple>().value();
        return fmt("%s(%s)", name,
                   util::join(cg->compileCallArguments(values, f.function().ftype().parameters()), ", "));
    }

    result_t operator()(const operator_::regexp::Match& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.match(%s)", self, args[0]);
    }

    result_t operator()(const operator_::regexp::MatchGroups& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.matchGroups(%s)", self, args[0]);
    }

    result_t operator()(const operator_::regexp::Find& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.find(%s)", self, args[0]);
    }

    result_t operator()(const operator_::regexp::TokenMatcher& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.tokenMatcher()", self);
    }

    result_t operator()(const operator_::regexp_match_state::AdvanceBytes& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.advance(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::regexp_match_state::AdvanceView& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.advance(%s)", self, args[0]);
    }

    // Optional
    result_t operator()(const operator_::optional::Deref& n) {
        return {fmt("::hilti::rt::optional::value(%s)", op0(n)), cxx::Side::LHS};
    }

    /// Port

    result_t operator()(const operator_::port::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::port::Unequal& n) { return binary(n, "!="); }

    result_t operator()(const operator_::port::Ctor& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Port(%s, %s)", args[0], args[1]);
    }

    result_t operator()(const operator_::port::Protocol& n) { return fmt("%s.protocol()", op0(n)); }

    // Set
    result_t operator()(const operator_::set::iterator::IncrPostfix& n) { return fmt("%s++", op0(n)); }
    result_t operator()(const operator_::set::iterator::IncrPrefix& n) { return fmt("++%s", op0(n)); }
    result_t operator()(const operator_::set::iterator::Deref& n) { return {fmt("*%s", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::set::iterator::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::set::iterator::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::set::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::set::In& n) { return fmt("%s.contains(%s)", op1(n), op0(n)); }
    result_t operator()(const operator_::set::Add& n) { return fmt("%s.insert(%s)", op0(n), op1(n)); }
    result_t operator()(const operator_::set::Delete& n) { return fmt("%s.erase(%s)", op0(n), op1(n)); }
    result_t operator()(const operator_::set::Size& n) { return fmt("%s.size()", op0(n)); }
    result_t operator()(const operator_::set::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::set::Clear& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.clear()", self);
    }

    /// stream::Iterator

    result_t operator()(const operator_::stream::iterator::Deref& n) { return {fmt("*%s", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::stream::iterator::IncrPostfix& n) { return fmt("%s++", op0(n)); }
    result_t operator()(const operator_::stream::iterator::IncrPrefix& n) { return fmt("++%s", op0(n)); }
    result_t operator()(const operator_::stream::iterator::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::iterator::Lower& n) { return fmt("%s < %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::iterator::LowerEqual& n) { return fmt("%s <= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::iterator::Greater& n) { return fmt("%s > %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::iterator::GreaterEqual& n) { return fmt("%s >= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::iterator::Difference& n) { return fmt("%s - %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::iterator::Sum& n) { return fmt("%s + %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::iterator::SumAssign& n) { return fmt("%s += %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::iterator::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::stream::iterator::Offset& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.offset()", self);
    }

    result_t operator()(const operator_::stream::iterator::IsFrozen& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.isFrozen()", self);
    }

    /// stream::View

    result_t operator()(const operator_::stream::view::Size& n) { return fmt("%s.size()", op0(n)); }
    result_t operator()(const operator_::stream::view::EqualView& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::view::EqualBytes& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::view::UnequalView& n) { return fmt("%s != %s", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::view::UnequalBytes& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::stream::view::Offset& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.offset()", self);
    }

    result_t operator()(const operator_::stream::view::InBytes& n) {
        return fmt("std::get<0>(%s.find(%s))", op1(n), op0(n));
    }
    result_t operator()(const operator_::stream::view::InView& n) {
        return fmt("std::get<0>(%s.find(%s))", op1(n), op0(n));
    }

    result_t operator()(const operator_::stream::view::AdvanceTo& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.advance(%s)", self, args[0]);
    }

    result_t operator()(const operator_::stream::view::AdvanceBy& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.advance(%s)", self, args[0]);
    }

    result_t operator()(const operator_::stream::view::AdvanceToNextData& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.advanceToNextData()", self);
    }

    result_t operator()(const operator_::stream::view::Limit& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.limit(%s)", self, args[0]);
    }

    result_t operator()(const operator_::stream::view::Find& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.find(%s)", self, args[0]);
    }


    result_t operator()(const operator_::stream::view::At& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.at(%s)", self, args[0]);
    }

    result_t operator()(const operator_::stream::view::StartsWith& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.startsWith(%s)", self, args[0]);
    }

    result_t operator()(const operator_::stream::view::SubIterators& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::stream::view::SubIterator& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.sub(%s)", self, args[0]);
    }

    result_t operator()(const operator_::stream::view::SubOffsets& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }


    // Stream

    result_t operator()(const operator_::stream::Size& n) { return fmt("%s.size()", op0(n)); }
    result_t operator()(const operator_::stream::SumAssignView& n) { return fmt("%s.append(%s)", op0(n), op1(n)); }
    result_t operator()(const operator_::stream::SumAssignBytes& n) { return fmt("%s.append(%s)", op0(n), op1(n)); }

    result_t operator()(const operator_::stream::Ctor& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Stream(%s)", args[0]);
    }

    result_t operator()(const operator_::stream::Freeze& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.freeze()", self);
    }

    result_t operator()(const operator_::stream::Unfreeze& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.unfreeze()", self);
    }

    result_t operator()(const operator_::stream::IsFrozen& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.isFrozen()", self);
    }

    result_t operator()(const operator_::stream::At& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.at(%s)", self, args[0]);
    }

    result_t operator()(const operator_::stream::Trim& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.trim(%s)", self, args[0]);
    }

    // String

    result_t operator()(const operator_::string::Sum& n) { return binary(n, "+"); }
    result_t operator()(const operator_::string::Size& n) { return fmt("::hilti::rt::string::size(%s)", op0(n)); }
    result_t operator()(const operator_::string::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::string::Unequal& n) { return binary(n, "!="); }

    result_t operator()(const operator_::string::Encode& n) {
        auto [self, args] = methodArguments(n);
        return fmt("::hilti::rt::Bytes(%s, %s)", self, args[0]);
    }

    result_t operator()(const operator_::string::Modulo& n) {
        if ( n.op1().type().isA<type::Tuple>() ) {
            if ( auto ctor = n.op1().tryAs<expression::Ctor>() ) {
                auto t = ctor->ctor().as<ctor::Tuple>().value();
                return fmt("::hilti::rt::fmt(%s, %s)", op0(n),
                           util::join(node::transform(t, [this](auto& x) { return cg->compile(x); }), ", "));
            }
        }

        return fmt("::hilti::rt::fmt(%s, %s)", op0(n), op1(n));
    }

    // Strong reference
    result_t operator()(const operator_::strong_reference::Deref& n) { return {fmt("(*%s)", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::strong_reference::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::strong_reference::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    /// Struct

    auto memberAccess(const expression::ResolvedOperatorBase& o, const std::string& self, const std::string& member) {
        return fmt("%s.%s", self, cxx::ID(member));
    }

    auto memberAccess(const expression::ResolvedOperatorBase& o, const std::string& member, bool lhs = false) {
        return memberAccess(o, cg->compile(o.op0(), lhs), member);
    }

    result_t structMember(const expression::ResolvedOperatorBase& o, const Expression& op1) {
        const auto& op0 = o.op0();
        auto id = op1.as<expression::Member>().id();
        auto attr = memberAccess(o, id);

        if ( auto f = op0.type().as<type::Struct>().field(id); f->isOptional() ) {
            auto d = f->default_();

            if ( lhs ) {
                if ( d )
                    return {fmt("::hilti::rt::optional::valueOrInit(%s, %s)", attr, cg->compile(*d)), cxx::Side::LHS};

                return {fmt("::hilti::rt::optional::valueOrInit(%s)", attr), cxx::Side::LHS};
            }

            if ( d )
                return fmt("%s.value_or(%s)", attr, cg->compile(*d));

            return fmt("::hilti::rt::optional::value(%s)", attr);
        }

        return {attr, cxx::Side::LHS};
    }

    result_t operator()(const operator_::struct_::MemberConst& n) { return structMember(n, n.op1()); }
    result_t operator()(const operator_::struct_::MemberNonConst& n) { return structMember(n, n.op1()); }

    result_t operator()(const operator_::struct_::MemberCall& n) {
        auto id = n.op1().as<expression::Member>().id();
        auto ft = n.op1().as<expression::Member>().type().as<type::Function>();
        auto args = n.op2().as<expression::Ctor>().ctor().as<ctor::Tuple>().value();

        std::vector<std::pair<Expression, bool>> zipped;

        zipped.reserve(args.size());
        for ( auto i = 0U; i < args.size(); i++ )
            zipped.emplace_back(args[i], ft.parameters()[i].kind() == declaration::parameter::Kind::InOut);

        return memberAccess(n,
                            fmt("%s(%s)", id,
                                util::join(util::transform(zipped,
                                                           [this](auto& x) { return cg->compile(x.first, x.second); }),
                                           ", ")),
                            false);
    }

    result_t operator()(const operator_::struct_::HasMember& n) {
        auto id = n.op1().as<expression::Member>().id();

        if ( auto f = n.op0().type().as<type::Struct>().field(id); f->isOptional() )
            return fmt("%s.has_value()", memberAccess(n, id));

        return "true";
    }

    result_t operator()(const operator_::struct_::TryMember& n) {
        auto id = n.op1().as<expression::Member>().id();
        assert(! lhs);

        if ( auto f = n.op0().type().as<type::Struct>().field(id); f->isOptional() ) {
            auto attr = memberAccess(n, id);

            if ( auto d = f->default_() )
                return memberAccess(n, fmt("value_or(%s)", cg->compile(*d)));

            return fmt("::hilti::rt::struct_::value_or_exception(%s)", attr);
        }

        return structMember(n, n.op1());
    }

    result_t operator()(const operator_::struct_::Unset& n) {
        auto id = n.op1().as<expression::Member>().id();
        return fmt("%s.reset()", memberAccess(n, std::move(id)));
    }

    /// Union

    unsigned int unionFieldIndex(const Expression& op0, const Expression& op1) {
        auto id = op1.as<expression::Member>().id();
        return op0.type().as<type::Union>().index(id);
    }

    result_t operator()(const operator_::union_::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::union_::Unequal& n) { return binary(n, "!="); }

    result_t operator()(const operator_::union_::MemberConst& n) {
        auto idx = unionFieldIndex(n.op0(), n.op1());
        return {fmt("::hilti::rt::union_::get<%u>(%s)", idx, op0(n)), cxx::Side::LHS};
    }

    result_t operator()(const operator_::union_::MemberNonConst& n) {
        auto idx = unionFieldIndex(n.op0(), n.op1());

        if ( lhs )
            return {fmt("::hilti::rt::union_::get_proxy<%u>(%s)", idx, op0(n)), cxx::Side::LHS};
        else
            return fmt("::hilti::rt::union_::get<%u>(%s)", idx, op0(n));
    }

    result_t operator()(const operator_::union_::HasMember& n) {
        auto idx = unionFieldIndex(n.op0(), n.op1());
        return fmt("(%s.index() == %u)", op0(n), idx);
    }

    // Signed integer

    result_t operator()(const operator_::signed_integer::CastToBool& n) { return fmt("::hilti::rt::Bool(%s)", op0(n)); }
    result_t operator()(const operator_::signed_integer::CastToInterval& n) {
        return fmt("::hilti::rt::Interval(hilti::rt::integer::safe<int64_t>(%" PRId64
                   ") * 1000000000, hilti::rt::Interval::NanosecondTag())",
                   op0(n));
    }
    result_t operator()(const operator_::signed_integer::CastToEnum& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("::hilti::rt::enum_::from_int<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }
    result_t operator()(const operator_::signed_integer::DecrPostfix& n) { return fmt("%s--", op0(n)); }
    result_t operator()(const operator_::signed_integer::DecrPrefix& n) { return fmt("--%s", op0(n)); }
    result_t operator()(const operator_::signed_integer::Difference& n) { return fmt("%s - %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::DifferenceAssign& n) {
        return fmt("%s -= %s", op0(n), op1(n));
    }
    result_t operator()(const operator_::signed_integer::Division& n) { return fmt("%s / %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::DivisionAssign& n) { return fmt("%s /= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::Greater& n) { return fmt("%s > %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::GreaterEqual& n) { return fmt("%s >= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::IncrPostfix& n) { return fmt("%s++", op0(n)); }
    result_t operator()(const operator_::signed_integer::IncrPrefix& n) { return fmt("++%s", op0(n)); }
    result_t operator()(const operator_::signed_integer::Lower& n) { return fmt("%s < %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::LowerEqual& n) { return fmt("%s <= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::Modulo& n) { return fmt("%s %% %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::Multiple& n) { return fmt("%s * %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::MultipleAssign& n) { return fmt("%s *= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::Power& n) {
        return fmt("::hilti::rt::pow(%s, %s)", op0(n), op1(n));
    }
    result_t operator()(const operator_::signed_integer::SignNeg& n) { return fmt("(-%s)", op0(n)); }
    result_t operator()(const operator_::signed_integer::Sum& n) { return fmt("%s + %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::SumAssign& n) { return fmt("%s += %s", op0(n), op1(n)); }
    result_t operator()(const operator_::signed_integer::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::signed_integer::CastToSigned& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::signed_integer::CastToUnsigned& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::signed_integer::CastToReal& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::signed_integer::CtorSigned8& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<int8_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::signed_integer::CtorSigned16& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<int16_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::signed_integer::CtorSigned32& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<int32_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::signed_integer::CtorSigned64& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<int64_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::signed_integer::CtorUnsigned8& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<int8_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::signed_integer::CtorUnsigned16& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<int16_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::signed_integer::CtorUnsigned32& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<int32_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::signed_integer::CtorUnsigned64& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<int64_t>(%s)", args[0]);
    }

    // Time

    result_t operator()(const operator_::time::DifferenceInterval& n) { return binary(n, "-"); }
    result_t operator()(const operator_::time::DifferenceTime& n) { return binary(n, "-"); }
    result_t operator()(const operator_::time::Equal& n) { return binary(n, "=="); }
    result_t operator()(const operator_::time::Greater& n) { return binary(n, ">"); }
    result_t operator()(const operator_::time::GreaterEqual& n) { return binary(n, ">="); }
    result_t operator()(const operator_::time::Lower& n) { return binary(n, "<"); }
    result_t operator()(const operator_::time::LowerEqual& n) { return binary(n, "<="); }
    result_t operator()(const operator_::time::Nanoseconds& n) { return fmt("%s.nanoseconds()", op0(n)); }
    result_t operator()(const operator_::time::Seconds& n) { return fmt("%s.seconds()", op0(n)); }
    result_t operator()(const operator_::time::SumInterval& n) { return binary(n, "+"); }
    result_t operator()(const operator_::time::Unequal& n) { return binary(n, "!="); }

    result_t operator()(const operator_::time::CtorSignedIntegerSecs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Time(%s, hilti::rt::Time::SecondTag())", args[0]);
    }

    result_t operator()(const operator_::time::CtorSignedIntegerNs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Time(%s, hilti::rt::Time::NanosecondTag())", args[0]);
    }

    result_t operator()(const operator_::time::CtorUnsignedIntegerSecs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Time(%s, hilti::rt::Time::SecondTag())", args[0]);
    }

    result_t operator()(const operator_::time::CtorUnsignedIntegerNs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Time(%s, hilti::rt::Time::NanosecondTag())", args[0]);
    }

    result_t operator()(const operator_::time::CtorRealSecs& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("::hilti::rt::Time(%f, hilti::rt::Time::SecondTag())", args[0]);
    }

    // Tuple

    result_t operator()(const operator_::tuple::CustomAssign& n) {
        auto t = n.operands()[0].as<expression::Ctor>().ctor().as<ctor::Tuple>().value();
        auto l = util::join(node::transform(t, [this](auto& x) { return cg->compile(x, true); }), ", ");
        return {fmt("std::tie(%s) = %s", l, op1(n)), cxx::Side::LHS};
    }

    result_t operator()(const operator_::tuple::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::tuple::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::tuple::Index& n) {
        auto i = n.op1().as<expression::Ctor>().ctor().as<ctor::UnsignedInteger>().value();
        return {fmt("std::get<%u>(%s)", i, op0(n)), cxx::Side::LHS};
    }

    result_t operator()(const operator_::tuple::Member& n) {
        auto id = n.op1().as<expression::Member>().id();
        auto elem = n.op0().type().as<type::Tuple>().elementByID(id);
        assert(elem);
        return {fmt("std::get<%u>(%s)", elem->first, op0(n)), cxx::Side::LHS};
    }

    // Unsigned integer

    result_t operator()(const operator_::unsigned_integer::BitAnd& n) { return fmt("(%s & %s)", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::BitOr& n) { return fmt("(%s | %s)", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::BitXor& n) { return fmt("(%s ^ %s)", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::CastToBool& n) {
        return fmt("::hilti::rt::Bool(%s)", op0(n));
    }
    result_t operator()(const operator_::unsigned_integer::CastToEnum& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("::hilti::rt::enum_::from_uint<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }
    result_t operator()(const operator_::unsigned_integer::CastToInterval& n) {
        return fmt("::hilti::rt::Interval(hilti::rt::integer::safe<uint64_t>(%" PRIu64
                   ") * 1000000000, hilti::rt::Interval::NanosecondTag())",
                   op0(n));
    }
    result_t operator()(const operator_::unsigned_integer::CastToTime& n) {
        return fmt("::hilti::rt::Time(hilti::rt::integer::safe<uint64_t>(%" PRIu64
                   ") * 1'000'000'000, hilti::rt::Time::NanosecondTag())",
                   op0(n));
    }
    result_t operator()(const operator_::unsigned_integer::DecrPostfix& n) { return fmt("%s--", op0(n)); }
    result_t operator()(const operator_::unsigned_integer::DecrPrefix& n) { return fmt("--%s", op0(n)); }
    result_t operator()(const operator_::unsigned_integer::Difference& n) { return fmt("%s - %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::DifferenceAssign& n) {
        return fmt("%s -= %s", op0(n), op1(n));
    }
    result_t operator()(const operator_::unsigned_integer::Division& n) { return fmt("%s / %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::DivisionAssign& n) {
        return fmt("%s /= %s", op0(n), op1(n));
    }
    result_t operator()(const operator_::unsigned_integer::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::Greater& n) { return fmt("%s > %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::GreaterEqual& n) { return fmt("%s >= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::IncrPostfix& n) { return fmt("%s++", op0(n)); }
    result_t operator()(const operator_::unsigned_integer::IncrPrefix& n) { return fmt("++%s", op0(n)); }
    result_t operator()(const operator_::unsigned_integer::Lower& n) { return fmt("%s < %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::LowerEqual& n) { return fmt("%s <= %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::Modulo& n) { return fmt("%s %% %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::Multiple& n) { return fmt("%s * %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::MultipleAssign& n) {
        return fmt("%s *= %s", op0(n), op1(n));
    }
    result_t operator()(const operator_::unsigned_integer::Negate& n) { return fmt("~%s", op0(n)); }
    result_t operator()(const operator_::unsigned_integer::Power& n) {
        return fmt("::hilti::rt::pow(%s, %s)", op0(n), op1(n));
    }
    result_t operator()(const operator_::unsigned_integer::ShiftLeft& n) { return fmt("(%s << %s)", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::ShiftRight& n) { return fmt("(%s >> %s)", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::SignNeg& n) { return fmt("(-%s)", op0(n)); }
    result_t operator()(const operator_::unsigned_integer::Sum& n) { return fmt("%s + %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::SumAssign& n) { return fmt("%s += %s", op0(n), op1(n)); }
    result_t operator()(const operator_::unsigned_integer::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::unsigned_integer::CastToSigned& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::unsigned_integer::CastToUnsigned& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::unsigned_integer::CastToReal& n) {
        auto t = n.op1().type().as<type::Type_>().typeValue();
        return fmt("static_cast<%s>(%s)", cg->compile(t, codegen::TypeUsage::Storage), op0(n));
    }

    result_t operator()(const operator_::unsigned_integer::CtorSigned8& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<uint8_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::unsigned_integer::CtorSigned16& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<uint16_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::unsigned_integer::CtorSigned32& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<uint32_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::unsigned_integer::CtorSigned64& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<uint64_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::unsigned_integer::CtorUnsigned8& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<uint8_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::unsigned_integer::CtorUnsigned16& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<uint16_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::unsigned_integer::CtorUnsigned32& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<uint32_t>(%s)", args[0]);
    }

    result_t operator()(const operator_::unsigned_integer::CtorUnsigned64& n) {
        auto args = tupleArguments(n, n.op1());
        return fmt("static_cast<uint64_t>(%s)", args[0]);
    }

    // Vector
    result_t operator()(const operator_::vector::iterator::IncrPostfix& n) { return fmt("%s++", op0(n)); }
    result_t operator()(const operator_::vector::iterator::IncrPrefix& n) { return fmt("++%s", op0(n)); }
    result_t operator()(const operator_::vector::iterator::Deref& n) { return {fmt("*%s", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::vector::iterator::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::vector::iterator::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    result_t operator()(const operator_::vector::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::vector::IndexConst& n) {
        return {fmt("%s[%s]", op0(n), op1(n)), cxx::Side::LHS};
    }
    result_t operator()(const operator_::vector::IndexNonConst& n) {
        return {fmt("%s[%s]", op0(n), op1(n)), cxx::Side::LHS};
    }
    result_t operator()(const operator_::vector::Size& n) { return fmt("%s.size()", op0(n)); }
    result_t operator()(const operator_::vector::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }
    result_t operator()(const operator_::vector::Sum& n) { return fmt("%s + %s", op0(n), op1(n)); }
    result_t operator()(const operator_::vector::SumAssign& n) { return fmt("%s += %s", op0(n), op1(n)); }

    result_t operator()(const operator_::vector::Back& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.back()", self);
    }

    result_t operator()(const operator_::vector::Front& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.front()", self);
    }

    result_t operator()(const operator_::vector::Assign& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.assign(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::vector::PushBack& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.emplace_back(%s)", self, args[0]);
    }

    result_t operator()(const operator_::vector::PopBack& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.pop_back()", self);
    }

    result_t operator()(const operator_::vector::Reserve& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.reserve(%s)", self, args[0]);
    }

    result_t operator()(const operator_::vector::Resize& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.resize(%s)", self, args[0]);
    }

    result_t operator()(const operator_::vector::At& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.iteratorAt(%s)", self, args[0]);
    }

    result_t operator()(const operator_::vector::SubRange& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.sub(%s, %s)", self, args[0], args[1]);
    }

    result_t operator()(const operator_::vector::SubEnd& n) {
        auto [self, args] = methodArguments(n);
        return fmt("%s.sub(%s)", self, args[0]);
    }

    // Weak reference
    result_t operator()(const operator_::weak_reference::Deref& n) { return {fmt("(*%s)", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::weak_reference::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::weak_reference::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }

    // Value reference
    result_t operator()(const operator_::value_reference::Deref& n) { return {fmt("(*%s)", op0(n)), cxx::Side::LHS}; }
    result_t operator()(const operator_::value_reference::Equal& n) { return fmt("%s == %s", op0(n), op1(n)); }
    result_t operator()(const operator_::value_reference::Unequal& n) { return fmt("%s != %s", op0(n), op1(n)); }
};

} // anonymous namespace

cxx::Expression CodeGen::compile(const expression::ResolvedOperator& o, bool lhs) {
    if ( auto x = Visitor(this, lhs).dispatch(Expression(o)) )
        return lhs ? _makeLhs(*x, o.type()) : *x;

    hilti::render(std::cerr, Expression(o));
    logger().internalError(fmt("operator failed to compile: %s", detail::renderOperatorPrototype(o)));
}
