// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/all.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/codegen/codegen.h>
#include <hilti/compiler/detail/cxx/all.h>

using namespace hilti;
using util::fmt;

using namespace hilti::detail;

namespace {

struct Visitor : public hilti::visitor::PreOrder<cxx::Expression, Visitor> {
    Visitor(CodeGen* cg, const cxx::Expression& expr, const Type& dst) : cg(cg), expr(expr), dst(dst) {}
    CodeGen* cg;
    const cxx::Expression& expr;
    const Type& dst;

    result_t operator()(const type::Bytes& src) {
        if ( auto t = dst.tryAs<type::Stream>() )
            return fmt("::hilti::rt::Stream(%s)", expr);

        logger().internalError(fmt("codegen: unexpected type coercion from bytes to %s", dst.typename_()));
    }

    result_t operator()(const type::Enum& src, position_t p) {
        if ( auto t = dst.tryAs<type::Bool>() ) {
            auto etype = p.node.as<Type>(); // preserve type ID
            auto id = cg->compile(etype, codegen::TypeUsage::Storage);
            return fmt("(%s != %s(%s::Undef))", expr, id, id);
        }

        logger().internalError(fmt("codegen: unexpected type coercion from enum to %s", dst.typename_()));
    }

    result_t operator()(const type::Error& src) {
        if ( auto t = dst.tryAs<type::Result>() )
            return fmt("%s(%s)", cg->compile(dst, codegen::TypeUsage::Storage), expr);

        logger().internalError(fmt("codegen: unexpected type coercion from error to %s", dst.typename_()));
    }

    result_t operator()(const type::Interval& src) {
        if ( auto t = dst.tryAs<type::Bool>() ) {
            auto id = cg->compile(src, codegen::TypeUsage::Storage);
            return fmt("(%s != hilti::rt::Interval())", expr);
        }

        logger().internalError(fmt("codegen: unexpected type coercion from interval to %s", dst.typename_()));
    }

    result_t operator()(const type::List& src) {
        if ( auto t = dst.tryAs<type::Set>() )
            return fmt("::hilti::rt::Set(%s)", expr);

        if ( auto t = dst.tryAs<type::Vector>() ) {
            auto x = cg->compile(t->elementType(), codegen::TypeUsage::Storage);

            std::string allocator;
            if ( auto def = cg->typeDefaultValue(t->elementType()) )
                allocator = fmt(", hilti::rt::vector::Allocator<%s, %s>", x, *def);

            return fmt("::hilti::rt::Vector<%s%s>(%s)", x, allocator, expr);
        }

        logger().internalError(fmt("codegen: unexpected type coercion from lisst to %s", dst.typename_()));
    }

    result_t operator()(const type::Optional& src) {
        if ( auto t = dst.tryAs<type::Optional>() ) {
            // Create tmp to avoid evaluation "expr" twice.
            auto tmp = cg->addTmp("opt", cg->compile(src, codegen::TypeUsage::Storage));
            return {fmt("(%s = (%s), %s.has_value() ? std::make_optional(*%s) : std::nullopt)", tmp, expr, tmp, tmp), cxx::Side::LHS};
        }

        if ( auto t = dst.tryAs<type::Bool>() )
            return fmt("%s.has_value()", expr);

        logger().internalError(fmt("codegen: unexpected type coercion from optional to %s", dst.typename_()));
    }

    result_t operator()(const type::StrongReference& src) {
        if ( auto t = dst.tryAs<type::Bool>() )
            return fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        if ( auto t = dst.tryAs<type::ValueReference>() )
            return fmt("%s.derefAsValue()", expr);

        if ( auto t = dst.tryAs<type::WeakReference>() )
            return fmt("::hilti::rt::WeakReference<%s>(%s)",
                       cg->compile(src.dereferencedType(), codegen::TypeUsage::Ctor), expr);

        if ( src.dereferencedType() == dst )
            return {fmt("(*%s)", expr), cxx::Side::LHS};

        logger().internalError(fmt("codegen: unexpected type coercion from %s to %s", Type(src), dst.typename_()));
    }

    result_t operator()(const type::Time& src) {
        if ( auto t = dst.tryAs<type::Bool>() ) {
            auto id = cg->compile(src, codegen::TypeUsage::Storage);
            return fmt("(%s != hilti::rt::Time())", expr);
        }

        logger().internalError(fmt("codegen: unexpected type coercion from time to %s", dst.typename_()));
    }


    result_t operator()(const type::Result& src) {
        if ( auto t = dst.tryAs<type::Bool>() )
            return fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        if ( auto t = dst.tryAs<type::Optional>() )
            return fmt("static_cast<%s>(%s)", cg->compile(dst, codegen::TypeUsage::Storage), expr);

        logger().internalError(fmt("codegen: unexpected type coercion from result to %s", dst.typename_()));
    }

    result_t operator()(const type::SignedInteger& src) {
        if ( dst.isA<type::Bool>() )
            return fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        if ( auto t = dst.tryAs<type::SignedInteger>() )
            return fmt("::hilti::rt::integer::safe<int%d_t>(%s)", t->width(), expr);

        if ( auto t = dst.tryAs<type::UnsignedInteger>() )
            return fmt("::hilti::rt::integer::safe<uint%d_t>(%s)", t->width(), expr);

        logger().internalError(fmt("codegen: unexpected type coercion from signed integer to %s", dst.typename_()));
    }

    result_t operator()(const type::Stream& src) {
        if ( auto t = dst.tryAs<type::stream::View>() )
            return fmt("%s.view()", expr);

        logger().internalError(fmt("codegen: unexpected type coercion from stream to %s", dst.typename_()));
    }

    result_t operator()(const type::Union& src, position_t p) {
        if ( auto t = dst.tryAs<type::Bool>() ) {
            auto utype = p.node.as<Type>(); // preserve type ID
            auto id = cg->compile(utype, codegen::TypeUsage::Storage);
            return fmt("(%s.index() > 0)", expr);
        }

        logger().internalError(fmt("codegen: unexpected type coercion from union to %s", dst.typename_()));
    }

    result_t operator()(const type::stream::View& src) {
        if ( auto t = dst.tryAs<type::Bytes>() )
            return fmt("%s.data()", expr);

        logger().internalError(fmt("codegen: unexpected type coercion from view<stream> to %s", dst.typename_()));
    }

    result_t operator()(const type::Tuple& src) {
        if ( auto t = dst.tryAs<type::Tuple>() ) {
            std::vector<cxx::Expression> exprs;

            assert(src.elements().size() == t->elements().size());
            for ( auto i = 0U; i < src.elements().size(); i++ )
                exprs.push_back(
                    cg->coerce(fmt("std::get<%d>(%s)", i, expr), src.elements()[i].type(), t->elements()[i].type()));

            return fmt("std::make_tuple(%s)", util::join(exprs, ", "));
        }

        logger().internalError(fmt("codegen: unexpected type coercion from tuple to %s", dst.typename_()));
    }

    result_t operator()(const type::UnsignedInteger& src) {
        if ( dst.isA<type::Bool>() )
            return fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        if ( auto t = dst.tryAs<type::SignedInteger>() )
            return fmt("::hilti::rt::integer::safe<int%d_t>(%s)", t->width(), expr);

        if ( auto t = dst.tryAs<type::UnsignedInteger>() )
            return fmt("::hilti::rt::integer::safe<uint%d_t>(%s)", t->width(), expr);

        logger().internalError(fmt("codegen: unexpected type coercion from unsigned integer to %s", dst.typename_()));
    }

    result_t operator()(const type::WeakReference& src) {
        if ( auto t = dst.tryAs<type::Bool>() )
            return fmt("::hilti::rt::Bool(static_cast<bool>(%s))", expr);

        if ( auto t = dst.tryAs<type::StrongReference>() )
            return fmt("::hilti::rt::StrongReference<%s>(%s)",
                       cg->compile(src.dereferencedType(), codegen::TypeUsage::Ctor), expr);

        if ( auto t = dst.tryAs<type::ValueReference>() )
            return fmt("%s.derefAsValue()", expr);

        if ( src.dereferencedType() == dst )
            return {fmt("(*%s)", expr), cxx::Side::LHS};

        logger().internalError(fmt("codegen: unexpected type coercion from weak reference to %s", dst.typename_()));
    }

    result_t operator()(const type::ValueReference& src) {
        if ( auto t = dst.tryAs<type::Bool>() )
            return cg->coerce(fmt("*%s", expr), src.dereferencedType(), dst);

        if ( auto t = dst.tryAs<type::ValueReference>();
             t && type::sameExceptForConstness(src.dereferencedType(), t->dereferencedType()) )
            return fmt("%s", expr);

        if ( auto t = dst.tryAs<type::StrongReference>() )
            return fmt("::hilti::rt::StrongReference<%s>(%s)",
                       cg->compile(src.dereferencedType(), codegen::TypeUsage::Ctor), expr);

        if ( auto t = dst.tryAs<type::WeakReference>() )
            return fmt("::hilti::rt::WeakReference<%s>(%s)",
                       cg->compile(src.dereferencedType(), codegen::TypeUsage::Ctor), expr);

        if ( src.dereferencedType() == dst )
            return {fmt("(*%s)", expr), cxx::Side::LHS};

        logger().internalError(fmt("codegen: unexpected type coercion from value reference to %s", dst.typename_()));
    }
};

} // anonymous namespace

cxx::Expression CodeGen::coerce(const cxx::Expression& e, const Type& src, const Type& dst) {
    if ( type::sameExceptForConstness(src, dst) )
        // If only difference is constness, nothing to do.
        return e;

    if ( auto t = dst.tryAs<type::Optional>(); t && ! src.isA<type::Optional>() )
        return fmt("%s(%s)", compile(dst, codegen::TypeUsage::Storage), e);

    if ( auto t = dst.tryAs<type::Result>() )
        return fmt("%s(%s)", compile(dst, codegen::TypeUsage::Storage), e);

    if ( dst.tryAs<type::ValueReference>() && ! type::isReferenceType(src) )
        return e;

    if ( auto nt = Visitor(this, e, dst).dispatch(src) )
        return *nt;

    logger().internalError(fmt("codegen: type %s unhandled for coercion", src.typename_()));
}
