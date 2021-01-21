// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/ctor.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/ctors/list.h>
#include <hilti/ast/ctors/result.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/error.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/list.h>
#include <hilti/ast/types/result.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/detail/visitors.h>
#include <hilti/compiler/plugin.h>
#include <hilti/global.h>

using namespace hilti;

namespace {

struct VisitorCtor : public visitor::PreOrder<std::optional<Ctor>, VisitorCtor> {
    VisitorCtor(const Type& dst, bitmask<CoercionStyle> style) : dst(dst), style(style) {}

    const Type& dst;
    bitmask<CoercionStyle> style;

    result_t operator()(const ctor::Enum& c) {
        if ( dst.isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            return ctor::Bool(c.value().id() != ID("Undef"), c.meta());

        return {};
    }

    result_t operator()(const ctor::Map& c) {
        if ( auto t = dst.tryAs<type::Map>() ) {
            std::vector<ctor::Map::Element> nelemns;
            for ( const auto& e : c.value() ) {
                auto k = hilti::coerceExpression(e.first, t->keyType(), style);
                auto v = hilti::coerceExpression(e.second, t->elementType(), style);

                if ( k && v )
                    nelemns.emplace_back(*k.coerced, *v.coerced);
                else
                    return {};
            }

            return ctor::Map(t->keyType(), t->elementType(), nelemns, c.meta());
        }

        return {};
    }

    result_t operator()(const ctor::Null& c) {
        if ( auto t = dst.tryAs<type::Optional>() )
            return ctor::Optional(t->dereferencedType());

        if ( auto t = dst.tryAs<type::StrongReference>() )
            return ctor::StrongReference(t->dereferencedType());

        if ( auto t = dst.tryAs<type::WeakReference>() )
            return ctor::WeakReference(t->dereferencedType());

        return {};
    }

    result_t operator()(const ctor::List& c) {
        if ( auto t = dst.tryAs<type::List>() ) {
            std::vector<Expression> nexprs;
            for ( const auto& e : c.value() ) {
                if ( auto x = hilti::coerceExpression(e, t->elementType(), CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return {};
            }
            return ctor::List(t->elementType(), std::move(nexprs), c.meta());
        }

        if ( auto t = dst.tryAs<type::Vector>() ) {
            auto dt = t->isWildcard() ? c.elementType() : t->elementType();

            std::vector<Expression> nexprs;
            for ( const auto& e : c.value() ) {
                if ( auto x = hilti::coerceExpression(e, dt, CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return {};
            }
            return ctor::Vector(dt, std::move(nexprs), c.meta());
        }

        if ( auto t = dst.tryAs<type::Set>() ) {
            auto dt = t->isWildcard() ? c.elementType() : t->elementType();

            std::vector<Expression> nexprs;
            for ( const auto& e : c.value() ) {
                if ( auto x = hilti::coerceExpression(e, dt, CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return {};
            }
            return ctor::Set(dt, std::move(nexprs), c.meta());
        }

        return {};
    }

    result_t operator()(const ctor::Real& c) {
        // Note: double->Integral constant conversions check 'non-narrowing' via
        // double->Int->double roundtrip - the generated code looks good.

        if ( auto t = dst.tryAs<type::SignedInteger>() ) {
            double d = c.value();

            if ( static_cast<double>(static_cast<int64_t>(d)) == d ) {
                switch ( t->isWildcard() ? 64 : t->width() ) {
                    case 8:
                        if ( static_cast<double>(int8_t(d)) == d )
                            return ctor::SignedInteger(int64_t(d), 8, c.meta());
                        break;

                    case 16:
                        if ( static_cast<double>(static_cast<int16_t>(d)) == d )
                            return ctor::SignedInteger(static_cast<int64_t>(d), 16, c.meta());
                        break;

                    case 32:
                        if ( static_cast<double>(static_cast<int32_t>(d)) == d )
                            return ctor::SignedInteger(static_cast<int64_t>(d), 32, c.meta());
                        break;

                    case 64: return ctor::SignedInteger(static_cast<int64_t>(d), 64, c.meta()); break;
                }
            }
        }

        if ( auto t = dst.tryAs<type::UnsignedInteger>() ) {
            double d = c.value();

            if ( static_cast<double>(static_cast<uint64_t>(d)) == d ) {
                switch ( t->isWildcard() ? 64 : t->width() ) {
                    case 8:
                        if ( static_cast<double>(static_cast<uint8_t>(d)) == d )
                            return ctor::UnsignedInteger(static_cast<uint64_t>(d), 8, c.meta());
                        break;

                    case 16:
                        if ( static_cast<double>(static_cast<uint16_t>(d)) == d )
                            return ctor::UnsignedInteger(uint64_t(d), 16, c.meta());
                        break;

                    case 32:
                        if ( static_cast<double>(static_cast<uint32_t>(d)) == d )
                            return ctor::UnsignedInteger(static_cast<uint64_t>(d), 32, c.meta());
                        break;

                    case 64: return ctor::UnsignedInteger(static_cast<uint64_t>(d), 64, c.meta()); break;
                }
            }
        }

        return {};
    }

    result_t operator()(const ctor::Set& c) {
        if ( auto t = dst.tryAs<type::Set>() ) {
            std::vector<Expression> nexprs;
            for ( const auto& e : c.value() ) {
                if ( auto x = hilti::coerceExpression(e, t->elementType(), style) )
                    nexprs.push_back(*x.coerced);
                else
                    return {};
            }
            return ctor::Set(t->elementType(), std::move(nexprs), c.meta());
        }

        return {};
    }

    result_t operator()(const ctor::SignedInteger& c) {
        if ( auto t = dst.tryAs<type::SignedInteger>() ) {
            if ( t->width() == 64 )
                return c;

            int64_t i = c.value();

            if ( t->isWildcard() )
                return ctor::SignedInteger(i, c.type().width(), c.meta());

            if ( auto [imin, imax] = util::signed_integer_range(t->width()); i >= imin && i <= imax )
                return ctor::SignedInteger(i, t->width(), c.meta());
        }

        if ( auto t = dst.tryAs<type::UnsignedInteger>(); t && c.value() >= 0 ) {
            auto u = static_cast<uint64_t>(c.value());

            if ( t->isWildcard() )
                return ctor::UnsignedInteger(u, c.type().width(), c.meta());

            if ( auto [zero, umax] = util::unsigned_integer_range(t->width()); u <= umax )
                return ctor::UnsignedInteger(u, t->width(), c.meta());
        }

        if ( auto t = dst.tryAs<type::Real>() ) {
            if ( static_cast<int64_t>(static_cast<double>(c.value())) == c.value() )
                return ctor::Real(static_cast<double>(c.value()));
        }

        if ( dst.isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            return ctor::Bool(c.value() != 0, c.meta());

        return {};
    }

    result_t operator()(const ctor::Vector& c) {
        if ( auto t = dst.tryAs<type::Vector>() ) {
            std::vector<Expression> nexprs;
            for ( const auto& e : c.value() ) {
                if ( auto x = hilti::coerceExpression(e, t->elementType(), style) )
                    nexprs.push_back(*x.coerced);
                else
                    return {};
            }
            return ctor::Vector(t->elementType(), std::move(nexprs), c.meta());
        }

        return {};
    }

    result_t operator()(const ctor::UnsignedInteger& c) {
        if ( auto t = dst.tryAs<type::UnsignedInteger>() ) {
            if ( t->width() == 64 )
                return c;

            uint64_t u = c.value();

            if ( t->isWildcard() )
                return ctor::UnsignedInteger(u, c.type().width(), c.meta());

            if ( auto [umin, umax] = util::unsigned_integer_range(t->width()); u >= umin && u <= umax )
                return ctor::UnsignedInteger(u, t->width(), c.meta());
        }

        if ( auto t = dst.tryAs<type::SignedInteger>(); t && static_cast<int64_t>(c.value()) >= 0 ) {
            auto i = static_cast<int64_t>(c.value());

            if ( t->isWildcard() )
                return ctor::SignedInteger(i, c.type().width(), c.meta());

            if ( auto [imin, imax] = util::signed_integer_range(t->width()); i >= imin && i <= imax )
                return ctor::SignedInteger(i, t->width(), c.meta());
        }

        if ( dst.isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            return ctor::Bool(c.value() != 0, c.meta());

        if ( auto t = dst.tryAs<type::Real>() ) {
            if ( static_cast<uint64_t>(static_cast<double>(c.value())) == c.value() )
                return ctor::Real(static_cast<double>(c.value()));
        }

        return {};
    }

    result_t operator()(const ctor::Tuple& c) {
        if ( auto t = dst.tryAs<type::Tuple>() ) {
            auto vc = c.value();
            auto vt = t.value().types();

            if ( vc.size() != vt.size() )
                return {};

            std::vector<Expression> coerced;
            coerced.reserve(vc.size());

            for ( auto i = std::make_pair(vc.cbegin(), vt.cbegin()); i.first != vc.cend(); ++i.first, ++i.second ) {
                if ( auto x = hilti::coerceExpression(*i.first, *i.second, CoercionStyle::TryAllForAssignment) ) {
                    coerced.push_back(*x.coerced);
                }
                else
                    return {};
            }

            return ctor::Tuple(std::move(coerced), c.meta());
        }

        return {};
    }

    result_t operator()(const ctor::Struct& c) {
        auto dst_ = dst;

        if ( (dst.isA<type::ValueReference>() || dst.isA<type::StrongReference>()) && ! type::isReferenceType(dst) )
            // Allow coercion from value to reference type with new instance.
            dst_ = dst.dereferencedType();

        if ( auto dtype = dst_.tryAs<type::Struct>() ) {
            auto stype = c.type().as<type::Struct>();

            std::set<ID> src_fields;
            for ( const auto& f : stype.fields() )
                src_fields.insert(f.id());

            std::set<ID> dst_fields;
            for ( const auto& f : dtype->fields() )
                dst_fields.insert(f.id());

            // Check for fields in ctor that type does not have.
            if ( ! util::set_difference(src_fields, dst_fields).empty() )
                return {};

            // Check for fields in type that ctor does not have, they must be
            // optional,
            auto x = util::set_difference(dst_fields, src_fields);

            std::set<ID> can_be_missing;

            for ( const auto& k : x ) {
                auto f = dtype->field(k);
                if ( f->isOptional() || f->default_() || f->type().isA<type::Function>() )
                    can_be_missing.insert(k);
            }

            x = util::set_difference(x, can_be_missing);

            if ( ! x.empty() )
                // Uninitialized fields.
                return {};

            // Coerce each field.
            std::vector<ctor::struct_::Field> nf;

            for ( const auto& sf : stype.fields() ) {
                auto df = dtype->field(sf.id());
                auto se = c.field(sf.id());
                assert(df && se);
                if ( auto ne = hilti::coerceExpression((*se).second, df->type(), style) )
                    nf.emplace_back(sf.id(), *ne.coerced);
                else
                    // Cannot coerce.
                    return {};
            }

            return ctor::Struct(std::move(nf), *dtype, c.meta());
        }

        return {};
    }
};

struct VisitorType : public visitor::PreOrder<std::optional<Type>, VisitorType> {
    VisitorType(const Type& dst, bitmask<CoercionStyle> style) : dst(dst), style(style) {}

    const Type& dst;
    bitmask<CoercionStyle> style;

    result_t operator()(const type::Enum& c) {
        if ( auto t = dst.tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            return dst;

        return {};
    }

    result_t operator()(const type::Null& c) {
        if ( auto t = dst.tryAs<type::Optional>() )
            return dst;

        if ( auto t = dst.tryAs<type::StrongReference>() )
            return dst;

        if ( auto t = dst.tryAs<type::WeakReference>() )
            return dst;

        return {};
    }

    result_t operator()(const type::Bytes& c) {
        if ( dst.tryAs<type::Stream>() && (style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall)) )
            return dst;

        return {};
    }

    result_t operator()(const type::Error& e) {
        if ( auto t = dst.tryAs<type::Result>() )
            return dst;

        return {};
    }

    result_t operator()(const type::List& e) {
        if ( auto t = dst.tryAs<type::Set>(); t && t->elementType() == e.elementType() )
            return dst;

        if ( auto t = dst.tryAs<type::Vector>(); t && t->elementType() == e.elementType() )
            return dst;

        return {};
    }

    result_t operator()(const type::Optional& r) {
        if ( auto t = dst.tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            return dst;

        return {};
    }

    result_t operator()(const type::StrongReference& r) {
        if ( auto t = dst.tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            return dst;

        if ( type::isReferenceType(dst) ) {
            if ( type::sameExceptForConstness(r.dereferencedType(), dst.dereferencedType()) )
                return dst;
        }

        if ( ! (style & CoercionStyle::Assignment) ) {
            if ( r.dereferencedType() == dst )
                return dst;
        }

        return {};
    }

    result_t operator()(const type::Result& r) {
        if ( auto t = dst.tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            return dst;

        if ( auto t = dst.tryAs<type::Optional>(); t && t->dereferencedType() == r.dereferencedType() )
            return dst;

        return {};
    }

    result_t operator()(const type::SignedInteger& src) {
        if ( dst.isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            return dst;

        if ( auto t = dst.tryAs<type::SignedInteger>() ) {
            if ( src.width() <= t->width() )
                return dst;
        }

        return {};
    }

    result_t operator()(const type::Stream& c) {
        if ( auto t = dst.tryAs<type::stream::View>() )
            return dst;

        return {};
    }

    result_t operator()(const type::stream::View& c) {
        if ( dst.tryAs<type::Bytes>() && (style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall)) )
            return dst;

        return {};
    }

    result_t operator()(const type::Type_& src) {
        if ( auto t = dst.tryAs<type::Type_>() ) {
            // We don't allow arbitrary coercions here, just (more or less) direct matches.
            if ( auto x = hilti::coerceType(src.typeValue(), t->typeValue(), CoercionStyle::TryDirectForMatching) )
                return type::Type_(*x);
        }

        return {};
    }

    result_t operator()(const type::Union& c) {
        if ( auto t = dst.tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            return dst;

        return {};
    }

    result_t operator()(const type::UnsignedInteger& src) {
        if ( dst.isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            return dst;

        if ( auto t = dst.tryAs<type::UnsignedInteger>() ) {
            if ( src.width() <= t->width() )
                return dst;
        }

        if ( auto t = dst.tryAs<type::SignedInteger>() ) {
            // As long as the target type has more bits, we can coerce.
            if ( src.width() < t->width() )
                return dst;
        }

        return {};
    }

    result_t operator()(const type::Tuple& src) {
        if ( auto t = dst.tryAs<type::Tuple>() ) {
            auto vc = src.types();
            auto vt = t->types();

            if ( vc.size() != vt.size() )
                return {};

            for ( auto i = std::make_pair(vc.cbegin(), vt.cbegin()); i.first != vc.cend(); ++i.first, ++i.second ) {
                if ( auto x = hilti::coerceType(*i.first, *i.second); ! x )
                    return {};
            }

            return dst;
        }

        return {};
    }

    result_t operator()(const type::ValueReference& r) {
        if ( auto t = dst.tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            return hilti::coerceType(r.dereferencedType(), dst, style);

        if ( type::isReferenceType(dst) ) {
            if ( type::sameExceptForConstness(r.dereferencedType(), dst.dereferencedType()) )
                return dst;
        }

        if ( r.dereferencedType() == dst )
            return dst;

        return {};
    }

    result_t operator()(const type::WeakReference& r) {
        if ( auto t = dst.tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            return dst;

        if ( type::isReferenceType(dst) ) {
            if ( type::sameExceptForConstness(r.dereferencedType(), dst.dereferencedType()) )
                return dst;
        }

        if ( ! (style & CoercionStyle::Assignment) ) {
            if ( r.dereferencedType() == dst )
                return dst;
        }

        return {};
    }
};

} // anonymous namespace

// Plugin-specific version just kicking off the local visitor.
std::optional<Ctor> detail::coerceCtor(Ctor c, const Type& dst, bitmask<CoercionStyle> style) {
    if ( auto nc = VisitorCtor(dst, style).dispatch(std::move(c)) )
        return *nc;

    return {};
}

// Plugin-specific version just kicking off the local visitor.
std::optional<Type> detail::coerceType(Type t, const Type& dst, bitmask<CoercionStyle> style) {
    if ( auto nt = VisitorType(dst, style).dispatch(std::move(t)) )
        return *nt;

    return {};
}
