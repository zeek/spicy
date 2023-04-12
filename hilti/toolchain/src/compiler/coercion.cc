// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/detail/visitor.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/operand-list.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/coercion.h>
#include <hilti/compiler/plugin.h>
#include <hilti/global.h>

using namespace hilti;
using namespace util;

namespace hilti::logging::debug {
inline const DebugStream Operator("operator");
} // namespace hilti::logging::debug


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
            std::vector<ctor::map::Element> nelemns;
            for ( const auto& e : c.value() ) {
                auto k = hilti::coerceExpression(e.key(), t->keyType(), style);
                auto v = hilti::coerceExpression(e.value(), t->elementType(), style);

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
                return ctor::SignedInteger(i, c.width(), c.meta());

            if ( auto [imin, imax] = util::signed_integer_range(t->width()); i >= imin && i <= imax )
                return ctor::SignedInteger(i, t->width(), c.meta());
        }

        if ( auto t = dst.tryAs<type::UnsignedInteger>(); t && c.value() >= 0 ) {
            auto u = static_cast<uint64_t>(c.value());

            if ( t->isWildcard() )
                return ctor::UnsignedInteger(u, c.width(), c.meta());

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
                return ctor::UnsignedInteger(u, c.width(), c.meta());

            if ( auto [umin, umax] = util::unsigned_integer_range(t->width()); u >= umin && u <= umax )
                return ctor::UnsignedInteger(u, t->width(), c.meta());
        }

        if ( auto t = dst.tryAs<type::SignedInteger>(); t && static_cast<int64_t>(c.value()) >= 0 ) {
            auto i = static_cast<int64_t>(c.value());

            if ( t->isWildcard() )
                return ctor::SignedInteger(i, c.width(), c.meta());

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
            auto ve = t.value().elements();

            if ( vc.size() != ve.size() )
                return {};

            std::vector<Expression> coerced;
            coerced.reserve(vc.size());

            for ( auto i = std::make_pair(vc.begin(), ve.begin()); i.first != vc.end(); ++i.first, ++i.second ) {
                if ( auto x =
                         hilti::coerceExpression(*i.first, (*i.second).type(), CoercionStyle::TryAllForAssignment) ) {
                    coerced.push_back(*x.coerced);
                }
                else
                    return {};
            }

            return ctor::Tuple(coerced, c.meta());
        }

        return {};
    }

    result_t operator()(const ctor::Struct& c) {
        auto dst_ = dst;

        if ( (dst.isA<type::ValueReference>() || dst.isA<type::StrongReference>()) && ! type::isReferenceType(dst) )
            // Allow coercion from value to reference type with new instance.
            dst_ = dst.dereferencedType();

        if ( auto dtype = dst_.tryAs<type::Struct>() ) {
            if ( ! dst_.typeID() )
                // Wait for this to be resolved.
                return {};

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

            // Check for fields that the type has, but are left out in the
            // ctor. These must all be either optional, internal, or have a
            // default.
            auto x = util::set_difference(dst_fields, src_fields);

            std::set<ID> can_be_missing;

            for ( const auto& k : x ) {
                auto f = dtype->field(k);
                if ( f->isOptional() || f->isInternal() || f->default_() || f->type().isA<type::Function>() )
                    can_be_missing.insert(k);
            }

            x = util::set_difference(x, can_be_missing);

            if ( ! x.empty() )
                // Uninitialized fields.
                return {};

            // Coerce each field.
            std::vector<ctor::struct_::Field> nf;

            for ( const auto& sf : stype.fields() ) {
                const auto& df = dtype->field(sf.id());
                const auto& se = c.field(sf.id());
                assert(df && se);
                if ( const auto& ne = hilti::coerceExpression(se->expression(), df->type(), style) )
                    nf.emplace_back(sf.id(), *ne.coerced);
                else
                    // Cannot coerce.
                    return {};
            }

            return ctor::Struct(std::move(nf), dst_, c.meta());
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

    result_t operator()(const type::Interval& c) {
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
        if ( auto t = dst.tryAs<type::Optional>() ) {
            const auto& s = r.dereferencedType();
            const auto& d = t->dereferencedType();

            if ( type::sameExceptForConstness(s, d) && (style & CoercionStyle::Assignment) )
                // Assignments copy, so it's safe to turn  into the
                // destination without considering constness.
                return dst;
        }

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

    result_t operator()(const type::Time& c) {
        if ( auto t = dst.tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            return dst;

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
            auto vc = src.elements();
            auto ve = t->elements();

            if ( vc.size() != ve.size() )
                return {};

            for ( auto i = std::make_pair(vc.begin(), ve.begin()); i.first != vc.end(); ++i.first, ++i.second ) {
                if ( auto x = hilti::coerceType((*i.first).type(), (*i.second).type()); ! x )
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

// Public version going through all plugins.
Result<Ctor> hilti::coerceCtor(Ctor c, const Type& dst, bitmask<CoercionStyle> style) {
    if ( c.type() == dst )
        return std::move(c);

    for ( auto p : plugin::registry().plugins() ) {
        if ( ! (p.coerce_ctor) )
            continue;

        if ( auto nc = (*p.coerce_ctor)(c, dst, style) )
            return *nc;
    }

    return result::Error("could not coeerce type for constructor");
}

static Result<Type> _coerceParameterizedType(const Type& src, const Type& dst, bitmask<CoercionStyle> style) {
    if ( src == dst )
        return dst;

    if ( src.typename_() != dst.typename_() )
        return {};

    if ( dst.isWildcard() )
        return src;

    auto params1 = src.typeParameters();
    auto params2 = dst.typeParameters();

    if ( params1.size() != params2.size() )
        return {};

    bool have_wildcard = false;

    for ( auto&& [p1, p2] : util::zip2(params1, params2) ) {
        // If we cannot get both parametres as types, we don't have a generic
        // node comparison for the individual parameters, so just stop here and
        // decline. (Note that the case of src == dst has been handled already,
        // that usually does it.)

        auto t1 = p1.tryAs<Type>();
        if ( ! t1 )
            return {};

        auto t2 = p2.tryAs<Type>();
        if ( ! t2 )
            return {};

        if ( ! coerceType(*t1, *t2, style) )
            return {};

        if ( t2->isWildcard() )
            have_wildcard = true;
    }

    // If one of the parameter types is a wildcard, we return the original type
    // instead of the coerced destination type. That's a heuristic that isn't
    // perfect, but will generally do the job. What we'd actually need is a
    // generic way to retype the type parameters, so that we could coerce them
    // individually. But we don't have that capability because all the types
    // compute them dynamically.
    return have_wildcard ? src : dst;
}

static Result<Type> _coerceType(const Type& src, const Type& dst, bitmask<CoercionStyle> style) {
    // TODO(robin): Not sure if this should/must replicate all the type coercion
    // login in coerceExpression(). If so, we should factor that out.
    // Update: I believe the answer is yes ... Added a few more cases, but this will
    // likely need more work.

    if ( src.typeID() && dst.typeID() ) {
        if ( *src.typeID() == *dst.typeID() )
            return dst;
        else
            return result::Error("type IDs do not match");
    }

    if ( src == dst )
        return src;

    if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
        if ( auto opt = dst.tryAs<type::Optional>() ) {
            if ( dst.isWildcard() )
                return dst;

            // All types converts into a corresponding optional.
            if ( auto x = coerceType(src, opt->dereferencedType(), style) )
                return {type::Optional(*x, src.meta())};
        }

        if ( auto opt = dst.tryAs<type::Result>() ) {
            if ( dst.isWildcard() )
                return dst;

            // All types converts into a corresponding result.
            if ( auto x = coerceType(src, opt->dereferencedType(), style) )
                return {type::Result(*x, src.meta())};
        }

        if ( auto x = dst.tryAs<type::ValueReference>(); x && ! type::isReferenceType(src) ) {
            // All types converts into a corresponding value_ref.
            if ( auto y = coerceType(src, x->dereferencedType(), style) )
                return {type::ValueReference(*x, src.meta())};
        }
    }

    if ( type::isParameterized(src) && type::isParameterized(dst) ) {
        if ( auto x = _coerceParameterizedType(src, dst, style) )
            return *x;
    }

    for ( auto p : plugin::registry().plugins() ) {
        if ( ! (p.coerce_type) )
            continue;

        if ( auto nt = (*p.coerce_type)(type::nonConstant(src), type::nonConstant(dst), style) )
            return type::nonConstant(*nt);
    }

    return result::Error("cannot coerce types");
}

// Public version going through all plugins.
Result<Type> hilti::coerceType(const Type& src, const Type& dst, bitmask<CoercionStyle> style) {
    return _coerceType(src, dst, style);
}

std::string hilti::to_string(bitmask<CoercionStyle> style) {
    std::vector<std::string> labels;

    if ( style & CoercionStyle::TryExactMatch )
        labels.emplace_back("try-exact-match");

    if ( style & CoercionStyle::TryConstPromotion )
        labels.emplace_back("try-const-promotion");

    if ( style & CoercionStyle::TryCoercion )
        labels.emplace_back("try-coercion");

    if ( style & CoercionStyle::Assignment )
        labels.emplace_back("assignment");

    if ( style & CoercionStyle::FunctionCall )
        labels.emplace_back("function-call");

    if ( style & CoercionStyle::OperandMatching )
        labels.emplace_back("operand-matching");

    if ( style & CoercionStyle::DisallowTypeChanges )
        labels.emplace_back("disallow-type-changes");

    if ( style & CoercionStyle::ContextualConversion )
        labels.emplace_back("contextual-conversion");

    return util::join(labels, ",");
};

Result<std::pair<bool, std::vector<Expression>>> hilti::coerceOperands(const node::Range<Expression>& exprs,
                                                                       const std::vector<operator_::Operand>& operands,
                                                                       bitmask<CoercionStyle> style) {
    int num_type_changes = 0;
    bool changed = false;
    std::vector<Node> transformed;

    if ( exprs.size() > operands.size() )
        return result::Error("more expressions than operands");

    for ( const auto&& [i, op] : util::enumerate(operands) ) {
        if ( i >= exprs.size() ) {
            // Running out of operands, must have a default or be optional.
            if ( op.default_ ) {
                transformed.emplace_back(*op.default_);
                changed = true;
            }
            else if ( op.optional ) {
                // transformed.push_back(hilti::expression::Ctor(hilti::ctor::Null()));
            }
            else
                return result::Error("stray operand");

            continue;
        }

        auto oat = operator_::type(op.type, exprs, node::Range<Expression>(transformed.begin(), transformed.end()));

        if ( ! oat ) {
            HILTI_DEBUG(logging::debug::Operator, util::fmt("  [param %d] could not look up operand type -> failure", i));
            return result::Error("could not look up operand type");
        }

        auto result = coerceExpression(exprs[i], *oat, style);
        if ( ! result ) {
            HILTI_DEBUG(logging::debug::Operator,
                        util::fmt("  [param %d] matching %s against %s -> failure", i, exprs[i].type(), *oat));
            return result::Error("could not match coercion operands");
        }

        HILTI_DEBUG(logging::debug::Operator,
                    util::fmt("  [param %d] matching %s against %s -> success: %s (coerced expression is %s) (%s)", i,
                              exprs[i].type(), *oat, result.coerced->type(),
                              (result.coerced->isConstant() ? "const" : "non-const"),
                              (result.consider_type_changed ? "type changed" : "type not changed")));

        // We check if the primary type of the alternative has changed. Only
        // one operand must change its primary type for an alternative to
        // match.
        if ( result.consider_type_changed && (++num_type_changes > 1 || style & CoercionStyle::DisallowTypeChanges) &&
             ! (style & CoercionStyle::FunctionCall) )
            return result::Error("no valid coercion found");

        transformed.emplace_back(*result.coerced);

        if ( result.nexpr )
            changed = true;
    }

    std::vector<Expression> x;
    x.reserve(transformed.size());
    for ( const auto& n : transformed )
        x.push_back(n.as<Expression>());

    return std::make_pair(changed, std::move(x));
}

static CoercedExpression _coerceExpression(const Expression& e, const Type& src, const Type& dst,
                                           bitmask<CoercionStyle> style, bool lhs) {
    if ( ! (style & CoercionStyle::_Recursing) )
        style |= CoercionStyle::_Recursing;

    const auto no_change = CoercedExpression(e);
    CoercedExpression _result;
    int _line = 0;

#define RETURN(x)                                                                                                      \
    {                                                                                                                  \
        _result = (x);                                                                                                 \
        _line = __LINE__;                                                                                              \
        goto exit;                                                                                                     \
    }

    const bool dst_is_const = type::isConstant(dst);
    const bool dst_is_mut = type::isMutable(dst);
    const bool e_is_const = e.isConstant();

    if ( dst.isA<type::Auto>() )
        // Always accept, we're going to update the auto type later.
        RETURN(no_change);

    if ( src.cxxID() && dst.cxxID() ) {
        if ( *src.cxxID() == *dst.cxxID() ) {
            RETURN(no_change);
        }
    }

    if ( src.typeID() && dst.typeID() ) {
        if ( *src.typeID() == *dst.typeID() ) {
            RETURN(no_change);
        }
        else {
            RETURN(result::Error());
        }
    }

    if ( style & CoercionStyle::TryExactMatch ) {
        if ( src == dst ) {
            if ( e_is_const == dst_is_const )
                RETURN(no_change);

            if ( style & CoercionStyle::OperandMatching && ! dst_is_mut )
                RETURN(no_change);
        }

        if ( e_is_const == dst_is_const && type::isParameterized(src) && type::isParameterized(dst) &&
             _coerceParameterizedType(src, dst, CoercionStyle::TryExactMatch) )
            RETURN(no_change); // can say no_change because we're in the ExactMatch case
    }

    if ( style & CoercionStyle::TryConstPromotion ) {
        if ( style & (CoercionStyle::OperandMatching | CoercionStyle::FunctionCall) ) {
            // Don't allow a constant value to match a non-constant operand.
            if ( e_is_const && (! dst_is_const) && dst_is_mut )
                RETURN(result::Error());

            if ( dst.isWildcard() && src.typename_() == dst.typename_() )
                RETURN(no_change);

            if ( src == dst )
                RETURN(no_change);

            if ( type::sameExceptForConstness(src, dst) ) {
                RETURN(no_change);
            }
        }

        if ( style & CoercionStyle::Assignment ) {
            if ( src == dst )
                RETURN(no_change);

            if ( type::sameExceptForConstness(src, dst) )
                RETURN(no_change);

            if ( dst.isWildcard() && src.typename_() == dst.typename_() )
                RETURN(no_change);
        }
    }

    else {
        if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
            // Don't allow assigning to a constant.
            if ( dst_is_const )
                RETURN(result::Error());
        }

        if ( style & CoercionStyle::OperandMatching ) {
            // Don't allow a constant value to match a non-constant operand.
            if ( e_is_const && !dst_is_const && dst_is_mut )
                RETURN(result::Error());
        }
    }

    if ( dst.isA<type::Any>() )
        // type::Any accepts anything without actual coercion.
        RETURN(no_change);

    if ( auto x = e.tryAs<expression::Member>() ) {
        // Make sure the expression remains a member expression, as we will
        // be expecting to cast it to that.
        if ( auto t = hilti::coerceType(x->type(), dst, style) ) {
            RETURN(CoercedExpression(src, expression::Member(x->id(), *t, x->meta())));
        }
        else
            RETURN(result::Error());
    }

    if ( auto o = dst.template tryAs<type::OperandList>() ) {
        // Match tuple against operands according to function call rules.
        HILTI_DEBUG(logging::debug::Operator, util::fmt("matching against call parameters"));
        logging::DebugPushIndent _(logging::debug::Operator);

        auto c = e.template tryAs<expression::Ctor>();
        if ( ! c )
            RETURN(CoercedExpression());

        // TODO(robin): Why do we need this block? We do a separate operand
        // matching afterwards, too.

        if ( auto t = c->ctor().template tryAs<hilti::ctor::Tuple>() ) {
            CoercionStyle function_style =
                (style & CoercionStyle::TryCoercion ? CoercionStyle::TryAllForFunctionCall :
                                                      CoercionStyle::TryDirectMatchForFunctionCall);
            if ( auto result = coerceOperands(t->value(), o->operands(), function_style) ) {
                if ( result->first ) {
                    RETURN(CoercedExpression(e.type(), expression::Ctor(hilti::ctor::Tuple(result->second))));
                }
                else {
                    RETURN(no_change);
                }
            }
        }

        RETURN(CoercedExpression());
    }

    if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
        if ( auto opt = dst.tryAs<type::Optional>() ) {
            if ( opt->isWildcard() )
                RETURN(no_change);

            // All types converts into a corresponding optional.
            if ( auto x = coerceExpression(e, opt->dereferencedType(), style) )
                RETURN(CoercedExpression(src, expression::Coerced(*x.coerced, dst, e.meta())));
        }

        if ( auto result = dst.tryAs<type::Result>() ) {
            if ( result->isWildcard() )
                RETURN(no_change);

            // All types convert into a corresponding result.
            if ( auto x = coerceExpression(e, result->dereferencedType(), style) )
                RETURN(CoercedExpression(src, expression::Coerced(*x.coerced, dst, e.meta())));
        }

        if ( auto x = dst.tryAs<type::ValueReference>(); x && ! type::isReferenceType(src) ) {
            // All types converts into a corresponding value_ref.
            if ( auto y = coerceExpression(e, x->dereferencedType(), style) )
                RETURN(CoercedExpression(src, expression::Coerced(*y.coerced, dst, e.meta())));
        }
    }

    if ( style & CoercionStyle::TryCoercion ) {
        if ( auto c = e.tryAs<expression::Ctor>() ) {
            if ( auto nc = hilti::coerceCtor(c->ctor(), dst, style) )
                RETURN(CoercedExpression(src, expression::Ctor(ctor::Coerced(c->ctor(), *nc, c->meta()), e.meta())));
        }

        if ( auto t = hilti::coerceType(src, dst, style) )
            // We wrap the expression into a coercion even if the new type is
            // the same as *dst*. That way the overloader has a way to
            // recognize that the types aren't identical.
            RETURN(CoercedExpression(src, expression::Coerced(e, *t, e.meta())));
    }

    _result = result::Error();

exit:
    if ( logger().isEnabled(logging::debug::Operator) )
        HILTI_DEBUG(logging::debug::Operator,
                    util::fmt("coercing %s %s (%s) to %s%s (%s) -> %s [%s] (%s) (#%d)",
                              (e_is_const ? "const" : "non-const"), to_node(src),
                              util::replace(src.typename_(), "hilti::type::", ""), (dst_is_const ? "" : "non-const "),
                              to_node(dst), util::replace(dst.typename_(), "hilti::type::", ""),
                              (_result ?
                                   util::fmt("%s %s (%s)", (_result.coerced->isConstant() ? "const" : "non-const"),
                                             _result.coerced->type(),
                                             util::replace(_result.coerced->type().typename_(), "hilti::type::", "")) :
                                   "fail"),
                              to_string(style), e.meta().location(), _line));

#undef RETURN

    return _result;
}

// Public version going through all plugins.
CoercedExpression hilti::coerceExpression(const Expression& e, const Type& src, const Type& dst,
                                          bitmask<CoercionStyle> style, bool lhs) {
    return _coerceExpression(e, src, dst, style, lhs);
}

// Public version going through all plugins.
CoercedExpression hilti::coerceExpression(const Expression& e, const Type& dst, bitmask<CoercionStyle> style, bool lhs) {
    return coerceExpression(e, e.type(), dst, style, lhs);
}


// Plugin-specific version just kicking off the local visitor.
std::optional<Ctor> hilti::detail::coerceCtor(Ctor c, const Type& dst, bitmask<CoercionStyle> style) {
    if ( ! (type::isResolved(c.type()) && type::isResolved(dst)) )
        return {};

    if ( auto nc = VisitorCtor(dst, style).dispatch(std::move(c)) )
        return *nc;

    return {};
}

// Plugin-specific version just kicking off the local visitor.
std::optional<Type> hilti::detail::coerceType(Type t, const Type& dst, bitmask<CoercionStyle> style) {
    if ( ! (type::isResolved(t) && type::isResolved(dst)) )
        return {};

    if ( auto nt = VisitorType(dst, style).dispatch(std::move(t)) )
        return *nt;

    return {};
}
