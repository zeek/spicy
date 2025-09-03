// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/null.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/expressions/coerced.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/any.h>
#include <hilti/ast/types/auto.h>
#include <hilti/ast/types/operand-list.h>
#include <hilti/ast/types/optional.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/result.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/coercer.h>
#include <hilti/compiler/plugin.h>

using namespace hilti;
using namespace util;

namespace hilti::logging::debug {
inline const DebugStream Coercer("coercer");
} // namespace hilti::logging::debug

namespace {

struct VisitorCtor : visitor::PreOrder {
    VisitorCtor(Builder* builder, QualifiedType* dst, bitmask<CoercionStyle> style)
        : builder(builder), dst(dst), style(style) {}

    Builder* builder;
    QualifiedType* dst = nullptr;
    bitmask<CoercionStyle> style;

    Ctor* result = nullptr;

    void operator()(ctor::Enum* n) final {
        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            result = builder->ctorBool(n->value()->id() != ID("Undef"), n->meta());
    }

    void operator()(ctor::Map* n) final {
        if ( auto* t = dst->type()->tryAs<type::Map>() ) {
            ctor::map::Elements nelemns;
            for ( const auto& e : n->value() ) {
                auto k = hilti::coerceExpression(builder, e->key(), t->keyType(), style);
                auto v = hilti::coerceExpression(builder, e->value(), t->elementType(), style);

                if ( k && v )
                    nelemns.emplace_back(builder->ctorMapElement(*k.coerced, *v.coerced));
                else
                    return;
            }

            result = builder->ctorMap(t->keyType(), t->elementType(), nelemns, n->meta());
        }
    }

    void operator()(ctor::Null* n) final {
        if ( auto* t = dst->type()->tryAs<type::Optional>() ) {
            result = builder->ctorOptional(t->dereferencedType());
            return;
        }

        if ( auto* t = dst->type()->tryAs<type::Result>(); t && t->dereferencedType()->type()->isA<type::Void>() ) {
            result = builder->ctorResult(t->dereferencedType());
            return;
        }

        if ( auto* t = dst->type()->tryAs<type::StrongReference>() ) {
            result = builder->ctorStrongReference(t->dereferencedType());
            return;
        }

        if ( auto* t = dst->type()->tryAs<type::WeakReference>() ) {
            result = builder->ctorWeakReference(t->dereferencedType());
            return;
        }
    }

    void operator()(ctor::List* n) final {
        if ( auto* t = dst->type()->tryAs<type::List>() ) {
            Expressions nexprs;
            for ( const auto& e : n->value() ) {
                if ( auto x =
                         hilti::coerceExpression(builder, e, t->elementType(), CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorList(t->elementType(), nexprs, n->meta());
        }

        if ( auto* t = dst->type()->tryAs<type::Vector>() ) {
            auto* dt = t->isWildcard() ? n->elementType() : t->elementType();

            Expressions nexprs;
            for ( const auto& e : n->value() ) {
                if ( auto x = hilti::coerceExpression(builder, e, dt, CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorVector(dt, nexprs, n->meta());
        }

        if ( auto* t = dst->type()->tryAs<type::Set>() ) {
            auto* dt = t->isWildcard() ? n->elementType() : t->elementType();

            Expressions nexprs;
            for ( const auto& e : n->value() ) {
                if ( auto x = hilti::coerceExpression(builder, e, dt, CoercionStyle::TryAllForAssignment) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorSet(dt, nexprs, n->meta());
        }
    }

    void operator()(ctor::Real* n) final {
        // Note: double->Integral constant conversions check 'non-narrowing' via
        // double->Int->double roundtrip - the generated code looks good.

        if ( auto* t = dst->type()->tryAs<type::SignedInteger>() ) {
            double d = n->value();

            if ( static_cast<double>(static_cast<int64_t>(d)) == d ) {
                switch ( t->isWildcard() ? 64 : t->width() ) {
                    case 8:
                        if ( static_cast<double>(int8_t(d)) == d )
                            result = builder->ctorSignedInteger(static_cast<int64_t>(d), 8, n->meta());
                        break;

                    case 16:
                        if ( static_cast<double>(static_cast<int16_t>(d)) == d )
                            result = builder->ctorSignedInteger(static_cast<int64_t>(d), 16, n->meta());
                        break;

                    case 32:
                        if ( static_cast<double>(static_cast<int32_t>(d)) == d )
                            result = builder->ctorSignedInteger(static_cast<int64_t>(d), 32, n->meta());
                        break;

                    case 64: result = builder->ctorSignedInteger(static_cast<int64_t>(d), 64, n->meta()); break;
                }
            }
        }

        if ( auto* t = dst->type()->tryAs<type::UnsignedInteger>() ) {
            double d = n->value();

            if ( static_cast<double>(static_cast<uint64_t>(d)) == d ) {
                switch ( t->isWildcard() ? 64 : t->width() ) {
                    case 8:
                        if ( static_cast<double>(static_cast<uint8_t>(d)) == d )
                            result = builder->ctorUnsignedInteger(static_cast<uint64_t>(d), 8, n->meta());
                        break;

                    case 16:
                        if ( static_cast<double>(static_cast<uint16_t>(d)) == d )
                            result = builder->ctorUnsignedInteger(static_cast<uint64_t>(d), 16, n->meta());
                        break;

                    case 32:
                        if ( static_cast<double>(static_cast<uint32_t>(d)) == d )
                            result = builder->ctorUnsignedInteger(static_cast<uint64_t>(d), 32, n->meta());
                        break;

                    case 64: result = builder->ctorUnsignedInteger(static_cast<uint64_t>(d), 64, n->meta()); break;
                }
            }
        }
    }

    void operator()(ctor::Set* n) final {
        if ( auto* t = dst->type()->tryAs<type::Set>() ) {
            Expressions nexprs;
            for ( const auto& e : n->value() ) {
                if ( auto x = hilti::coerceExpression(builder, e, t->elementType(), style) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorSet(t->elementType(), nexprs, n->meta());
        }
    }

    void operator()(ctor::SignedInteger* n) final {
        if ( auto* t = dst->type()->tryAs<type::SignedInteger>() ) {
            if ( t->width() == 64 ) {
                result = n;
                return;
            }

            int64_t i = n->value();

            if ( t->isWildcard() ) {
                result = builder->ctorSignedInteger(i, n->width(), n->meta());
                return;
            }

            else if ( auto [imin, imax] = util::signedIntegerRange(t->width()); i >= imin && i <= imax ) {
                result = builder->ctorSignedInteger(i, t->width(), n->meta());
                return;
            }
        }

        if ( auto* t = dst->type()->tryAs<type::UnsignedInteger>(); t && n->value() >= 0 ) {
            auto u = static_cast<uint64_t>(n->value());

            if ( t->isWildcard() ) {
                result = builder->ctorUnsignedInteger(u, n->width(), n->meta());
                return;
            }

            else if ( auto [zero, umax] = util::unsignedIntegerRange(t->width()); u <= umax ) {
                result = builder->ctorUnsignedInteger(u, t->width(), n->meta());
                return;
            }
        }

        if ( dst->type()->isA<type::Real>() ) {
            if ( static_cast<int64_t>(static_cast<double>(n->value())) == n->value() ) {
                result = builder->ctorReal(static_cast<double>(n->value()));
                return;
            }
        }

        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) ) {
            result = builder->ctorBool(n->value() != 0, n->meta());
            return;
        }

        if ( auto* t = dst->type()->tryAs<type::Bitfield>(); t && n->value() >= 0 ) {
            auto u = static_cast<uint64_t>(n->value());
            if ( auto [umin, umax] = util::unsignedIntegerRange(t->width()); u >= umin && u <= umax ) {
                result = builder->ctorUnsignedInteger(u, t->width(), n->meta());
                return;
            }
        }
    }

    void operator()(ctor::String* n) final {
        if ( dst->type()->isA<type::Error>() && (style & CoercionStyle::ContextualConversion) ) {
            result = builder->ctorError(n->value(), n->meta());
            return;
        }
    }

    void operator()(ctor::Vector* n) final {
        if ( auto* t = dst->type()->tryAs<type::Vector>() ) {
            Expressions nexprs;
            for ( const auto& e : n->value() ) {
                if ( auto x = hilti::coerceExpression(builder, e, t->elementType(), style) )
                    nexprs.push_back(*x.coerced);
                else
                    return;
            }
            result = builder->ctorVector(t->elementType(), nexprs, n->meta());
        }
    }

    void operator()(ctor::UnsignedInteger* n) final {
        if ( auto* t = dst->type()->tryAs<type::UnsignedInteger>() ) {
            if ( t->width() == 64 ) {
                result = n;
                return;
            }

            uint64_t u = n->value();

            if ( t->isWildcard() ) {
                result = builder->ctorUnsignedInteger(u, n->width(), n->meta());
                return;
            }

            else if ( auto [umin, umax] = util::unsignedIntegerRange(t->width()); u >= umin && u <= umax ) {
                result = builder->ctorUnsignedInteger(u, t->width(), n->meta());
                return;
            }
        }

        if ( auto* t = dst->type()->tryAs<type::SignedInteger>(); t && static_cast<int64_t>(n->value()) >= 0 ) {
            auto i = static_cast<int64_t>(n->value());

            if ( t->isWildcard() ) {
                result = builder->ctorSignedInteger(i, n->width(), n->meta());
                return;
            }

            else if ( auto [imin, imax] = util::signedIntegerRange(t->width()); i >= imin && i <= imax ) {
                result = builder->ctorSignedInteger(i, t->width(), n->meta());
                return;
            }
        }

        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) ) {
            result = builder->ctorBool(n->value() != 0, n->meta());
            return;
        }

        if ( dst->type()->isA<type::Real>() ) {
            if ( static_cast<uint64_t>(static_cast<double>(n->value())) == n->value() ) {
                result = builder->ctorReal(static_cast<double>(n->value()));
                return;
            }
        }

        if ( auto* t = dst->type()->tryAs<type::Bitfield>() ) {
            uint64_t u = n->value();
            if ( auto [umin, umax] = util::unsignedIntegerRange(t->width()); u >= umin && u <= umax ) {
                result = builder->ctorUnsignedInteger(u, t->width(), n->meta());
                return;
            }
        }
    }

    void operator()(ctor::Tuple* n) final {
        if ( auto* t = dst->type()->tryAs<type::Tuple>() ) {
            auto vc = n->value();
            auto ve = t->elements();

            if ( vc.size() != ve.size() )
                return;

            Expressions coerced;
            coerced.reserve(vc.size());

            for ( auto i = std::make_pair(vc.begin(), ve.begin()); i.first != vc.end(); ++i.first, ++i.second ) {
                if ( auto x = hilti::coerceExpression(builder, *i.first, (*i.second)->type(),
                                                      CoercionStyle::TryAllForAssignment) ) {
                    coerced.push_back(*x.coerced);
                }
                else
                    return;
            }

            result = builder->ctorTuple(coerced, n->meta());
        }
    }

    void operator()(ctor::Struct* n) final {
        auto* dst_ = dst;

        if ( dst->type()->isA<type::ValueReference>() || dst->type()->isA<type::StrongReference>() )
            // Allow coercion from value to reference type with new instance.
            dst_ = dst->type()->dereferencedType();

        if ( auto* dtype = dst_->type()->tryAs<type::Struct>() ) {
            if ( ! dst_->type() )
                // Wait for this to be resolved.
                return;

            auto* stype = n->stype();

            std::set<ID> src_fields;
            for ( const auto& f : stype->fields() )
                src_fields.insert(f->id());

            std::set<ID> dst_fields;
            for ( const auto& f : dtype->fields() )
                dst_fields.insert(f->id());

            // Check for fields in ctor that type does not have.
            if ( ! util::setDifference(src_fields, dst_fields).empty() )
                return;

            // Check for fields that the type has, but are left out in the
            // ctor. These must all be either optional, internal, or have a
            // default.
            auto x = util::setDifference(dst_fields, src_fields);

            std::set<ID> can_be_missing;

            for ( const auto& k : x ) {
                auto* f = dtype->field(k);
                if ( f->isOptional() || f->isInternal() || f->default_() || f->type()->type()->isA<type::Function>() )
                    can_be_missing.insert(k);
            }

            x = util::setDifference(x, can_be_missing);

            if ( ! x.empty() )
                // Uninitialized fields.
                return;

            // Coerce each field.
            ctor::struct_::Fields nf;

            for ( const auto& sf : stype->fields() ) {
                const auto& df = dtype->field(sf->id());
                const auto& se = n->field(sf->id());
                assert(df && se);
                if ( const auto& ne = hilti::coerceExpression(builder, se->expression(), df->type(), style) )
                    nf.emplace_back(builder->ctorStructField(sf->id(), *ne.coerced));
                else
                    // Cannot coerce.
                    return;
            }

            result = builder->ctorStruct(nf, dst_, n->meta());
        }

        if ( auto* dtype = dst_->type()->tryAs<type::Bitfield>() ) {
            if ( ! dst_->type()->typeID() )
                // Wait for this to be resolved.
                return;

            auto* stype = n->type()->type()->as<type::Struct>();

            std::set<ID> src_fields;
            for ( const auto& f : stype->fields() )
                src_fields.insert(f->id());

            std::set<ID> dst_fields;
            for ( const auto& f : dtype->bits() )
                dst_fields.insert(f->id());

            // Check for fields in ctor that type does not have.
            if ( ! util::setDifference(src_fields, dst_fields).empty() )
                return;

            // Coerce each field.
            ctor::bitfield::BitRanges bits;

            for ( const auto& sf : stype->fields() ) {
                const auto& dbits = dtype->bits(sf->id());
                const auto& se = n->field(sf->id());
                assert(dbits && se);
                if ( const auto& ne = coerceExpression(builder, se->expression(), dbits->itemType(), style) )
                    bits.emplace_back(builder->ctorBitfieldBitRange(sf->id(), *ne.coerced));
                else
                    // Cannot coerce.
                    return;
            }

            result = builder->ctorBitfield(bits, builder->qualifiedType(dtype, Constness::Const), n->meta());
            return;
        }
    }
};

struct VisitorType : visitor::PreOrder {
    explicit VisitorType(Builder* builder, QualifiedType* src, QualifiedType* dst, bitmask<CoercionStyle> style)
        : builder(builder), src(src), dst(dst), style(style) {}

    Builder* builder;
    QualifiedType* src = nullptr;
    QualifiedType* dst = nullptr;
    bitmask<CoercionStyle> style;

    QualifiedType* result = nullptr;

    void operator()(type::Enum* n) final {
        if ( auto* t = dst->type()->tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            result = dst;
    }

    void operator()(type::Interval* n) final {
        if ( auto* t = dst->type()->tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            result = dst;
    }

    void operator()(type::Null* n) final {
        if ( dst->type()->isA<type::Optional>() )
            result = dst;
        else if ( auto* t = dst->type()->tryAs<type::Result>(); t && t->dereferencedType()->type()->isA<type::Void>() )
            result = dst;
        else if ( dst->type()->isA<type::StrongReference>() )
            result = dst;
        else if ( dst->type()->isA<type::WeakReference>() )
            result = dst;
    }

    void operator()(type::Bytes* n) final {
        if ( dst->type()->tryAs<type::Stream>() && (style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall)) )
            result = dst;
    }

    void operator()(type::Error* n) final {
        if ( dst->type()->isA<type::Result>() )
            result = dst;
    }

    void operator()(type::List* n) final {
        if ( auto* t = dst->type()->tryAs<type::Set>(); t && type::same(t->elementType(), n->elementType()) )
            result = dst;

        else if ( auto* t = dst->type()->tryAs<type::Vector>(); t && type::same(t->elementType(), n->elementType()) )
            result = dst;
    }

    void operator()(type::Optional* n) final {
        if ( auto* t = dst->type()->tryAs<type::Optional>() ) {
            const auto& s = n->dereferencedType();
            const auto& d = t->dereferencedType();

            if ( type::sameExceptForConstness(s, d) && (style & CoercionStyle::Assignment) ) {
                // Assignments copy, so it's safe to turn  into the
                // destination without considering constness.
                result = dst;
                return;
            }
        }

        if ( auto* t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            result = dst;
    }

    void operator()(type::StrongReference* n) final {
        if ( auto* t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t ) {
            result = dst;
            return;
        }

        if ( dst->type()->isReferenceType() ) {
            if ( type::sameExceptForConstness(n->dereferencedType(), dst->type()->dereferencedType()) ) {
                result = dst->type()->dereferencedType()->isWildcard() ? src : dst;
                return;
            }
        }

        if ( ! (style & CoercionStyle::Assignment) ) {
            if ( type::same(n->dereferencedType(), dst) ) {
                result = dst;
            }
        }
    }

    void operator()(type::String* n) final {
        if ( dst->type()->isA<type::Error>() && (style & CoercionStyle::ContextualConversion) ) {
            result = dst;
            return;
        }
    }

    void operator()(type::Time* n) final {
        if ( auto* t = dst->type()->tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            result = dst;
    }

    void operator()(type::Result* n) final {
        if ( auto* t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t )
            result = dst;

        else if ( auto* t = dst->type()->tryAs<type::Optional>();
                  t && type::same(t->dereferencedType(), n->dereferencedType()) )
            result = dst;
    }

    void operator()(type::SignedInteger* n) final {
        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) )
            result = dst;

        else if ( auto* t = dst->type()->tryAs<type::SignedInteger>() ) {
            if ( n->width() <= t->width() )
                result = dst;
        }
    }

    void operator()(type::Stream* n) final {
        if ( dst->type()->isA<type::stream::View>() )
            result = dst;
    }

    void operator()(type::stream::View* n) final {
        if ( dst->type()->tryAs<type::Bytes>() && (style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall)) )
            result = dst;
    }

    void operator()(type::Type_* n) final {
        if ( auto* lt = dst->type()->tryAs<type::Library>(); lt && lt->cxxName() == "::hilti::rt::TypeInfo*" )
            result = dst->recreateAsConst(builder->context());

        else if ( auto* t = dst->type()->tryAs<type::Type_>() ) {
            if ( type::sameExceptForConstness(n->typeValue(), t->typeValue()) )
                result = src;
        }

        // Allow ctor calls.
        if ( auto x = hilti::coerceType(builder, n->typeValue(), dst, CoercionStyle::TryDirectForMatching) )
            result = n->typeValue();
    }

    void operator()(type::Union* n) final {
        if ( auto* t = dst->type()->tryAs<type::Bool>(); t && (style & CoercionStyle::ContextualConversion) )
            result = dst;
    }

    void operator()(type::UnsignedInteger* n) final {
        if ( dst->type()->isA<type::Bool>() && (style & CoercionStyle::ContextualConversion) ) {
            result = dst;
            return;
        }

        if ( auto* t = dst->type()->tryAs<type::UnsignedInteger>() ) {
            if ( n->width() <= t->width() ) {
                result = dst;
                return;
            }
        }

        if ( auto* t = dst->type()->tryAs<type::SignedInteger>() ) {
            // As long as the target type has more bits, we can coerce.
            if ( n->width() < t->width() ) {
                result = dst;
                return;
            }
        }

        if ( auto* t = dst->type()->tryAs<type::Bitfield>() ) {
            if ( n->width() <= t->width() ) {
                result = dst;
                return;
            }
        }
    }

    void operator()(type::Tuple* n) final {
        if ( auto* t = dst->type()->tryAs<type::Tuple>() ) {
            auto vc = n->elements();
            auto ve = t->elements();

            if ( vc.size() != ve.size() )
                return;

            for ( auto i = std::make_pair(vc.begin(), ve.begin()); i.first != vc.end(); ++i.first, ++i.second ) {
                if ( auto x = hilti::coerceType(builder, (*i.first)->type(), (*i.second)->type()); ! x )
                    return;
            }

            result = dst;
        }
    }

    void operator()(type::ValueReference* n) final {
        if ( auto* t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t ) {
            if ( auto t = hilti::coerceType(builder, n->dereferencedType(), dst, style) )
                result = *t;

            return;
        }

        if ( dst->type()->isReferenceType() ) {
            if ( type::sameExceptForConstness(n->dereferencedType(), dst->type()->dereferencedType()) ) {
                result = dst;
                return;
            }
        }

        if ( type::same(n->dereferencedType(), dst) ) {
            result = dst;
            return;
        }
    }

    void operator()(type::WeakReference* n) final {
        if ( auto* t = dst->type()->tryAs<type::Bool>(); (style & CoercionStyle::ContextualConversion) && t ) {
            result = dst;
            return;
        }

        if ( dst->type()->isReferenceType() ) {
            if ( type::sameExceptForConstness(n->dereferencedType(), dst->type()->dereferencedType()) ) {
                result = dst;
                return;
            }
        }

        if ( ! (style & CoercionStyle::Assignment) ) {
            if ( type::same(n->dereferencedType(), dst) ) {
                result = dst;
                return;
            }
        }
    }
};

} // anonymous namespace

// Public version going through all plugins.
Result<Ctor*> hilti::coerceCtor(Builder* builder, Ctor* c, QualifiedType* dst, bitmask<CoercionStyle> style) {
    if ( type::same(c->type(), dst) )
        return c;

    for ( const auto& p : plugin::registry().plugins() ) {
        if ( ! (p.coerce_ctor) )
            continue;

        if ( auto* nc = (*p.coerce_ctor)(builder, c, dst, style) )
            return nc;
    }

    return result::Error("could not coerce type for constructor");
}

static Result<QualifiedType*> coerceTypeBackend(Builder* builder, QualifiedType* src_, QualifiedType* dst_,
                                                bitmask<CoercionStyle> style) {
    // TODO(robin): Not sure if this should/must replicate all the type coercion
    // login in coerceExpression(). If so, we should factor that out.
    // Update: I believe the answer is yes ... Added a few more cases, but this will
    // likely need more work.

    auto* src = src_;

    if ( auto* name = src->type()->tryAs<type::Name>() ) {
        if ( auto* d = name->resolvedDeclaration() )
            src = d->type();
        else
            return result::Error("type name has not been resolved");
    }

    auto* dst = dst_;

    if ( auto* name = dst->type()->tryAs<type::Name>() ) {
        if ( auto* d = name->resolvedDeclaration() )
            dst = d->type();
        else
            return result::Error("type name has not been resolved");
    }

    if ( type::same(src, dst) )
        return src_;

    if ( style & CoercionStyle::Assignment ) {
        if ( type::sameExceptForConstness(src, dst) )
            return dst_;
    }

    if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
        if ( auto* opt = dst->type()->tryAs<type::Optional>() ) {
            if ( dst->type()->isWildcard() )
                return dst;

            // All types converts into a corresponding optional.
            if ( auto x = coerceTypeBackend(builder, src, opt->dereferencedType(), style | CoercionStyle::Assignment) )
                return builder->qualifiedType(builder->typeOptional(*x, src->meta()), Constness::Mutable);
        }

        if ( auto* opt = dst->type()->tryAs<type::Result>() ) {
            if ( dst->type()->isWildcard() )
                return dst;

            // All types converts into a corresponding result.
            if ( auto x = coerceTypeBackend(builder, src, opt->dereferencedType(), style) )
                return builder->qualifiedType(builder->typeResult(*x, src->meta()), Constness::Mutable);
        }

        if ( auto* x = dst->type()->tryAs<type::ValueReference>(); x && ! src->type()->isReferenceType() ) {
            // All types converts into a corresponding value_ref.
            if ( auto y = coerceTypeBackend(builder, src, x->dereferencedType(), style) )
                return builder->qualifiedType(builder->typeValueReference(dst, src->meta()), Constness::Mutable);
        }
    }

    for ( const auto& p : plugin::registry().plugins() ) {
        if ( ! (p.coerce_type) )
            continue;

        if ( auto* nt = (*p.coerce_type)(builder, src, dst, style) )
            return nt;
    }

    return result::Error("cannot coerce types");
}

// Public version going through all plugins.
Result<QualifiedType*> hilti::coerceType(Builder* builder, QualifiedType* src, QualifiedType* dst,
                                         bitmask<CoercionStyle> style) {
    return coerceTypeBackend(builder, src, dst, style);
}

std::string hilti::to_string(bitmask<CoercionStyle> style) {
    std::vector<std::string> labels;

    if ( style & CoercionStyle::TryExactMatch )
        labels.emplace_back("try-exact-match");

    if ( style & CoercionStyle::TryConstPromotion )
        labels.emplace_back("try-const-promotion");

    if ( style & CoercionStyle::TryCoercion )
        labels.emplace_back("try-coercion");

    if ( style & CoercionStyle::TryCoercionWithinSameType )
        labels.emplace_back("try-coercion-within-same-type");

    if ( style & CoercionStyle::TryDeref )
        labels.emplace_back("try-deref");

    if ( style & CoercionStyle::Assignment )
        labels.emplace_back("assignment");

    if ( style & CoercionStyle::FunctionCall )
        labels.emplace_back("function-call");

    if ( style & CoercionStyle::DisallowTypeChanges )
        labels.emplace_back("disallow-type-changes");

    if ( style & CoercionStyle::ContextualConversion )
        labels.emplace_back("contextual-conversion");

    return util::join(labels, ",");
};

Result<std::pair<bool, Expressions>> hilti::coerceOperands(Builder* builder, operator_::Kind kind,
                                                           const Expressions& exprs,
                                                           const operator_::Operands& operands,
                                                           bitmask<CoercionStyle> style) {
    int num_type_changes = 0;
    bool changed = false;
    Expressions transformed;

    if ( exprs.size() > operands.size() )
        return result::Error("more expressions than operands");

    for ( const auto&& [i, op] : util::enumerate(operands) ) {
        if ( i >= exprs.size() ) {
            // Running out of operands, must have a default or be optional.
            if ( auto* d = op->default_() ) {
                transformed.emplace_back(d);
                changed = true;
            }
            else if ( op->isOptional() ) {
                // transformed.push_back(hilti::expression::Ctor(hilti::builder->ctorNull()));
            }
            else
                return result::Error("stray operand");

            continue;
        }

        if ( exprs[i]->type()->type()->isA<type::Null>() ) {
            if ( auto* d = op->default_() ) {
                transformed.emplace_back(d);
                changed = true;
                continue;
            }
            else if ( op->isOptional() )
                continue;
        }

        bool needs_mutable = false;
        QualifiedType* oat = op->type();

        switch ( op->kind() ) {
            case parameter::Kind::In:
            case parameter::Kind::Copy: needs_mutable = false; break;
            case parameter::Kind::InOut: needs_mutable = true; break;
            case parameter::Kind::Unknown: logger().internalError("unknown operand kind"); break;
        }

        if ( needs_mutable ) {
            auto* t = exprs[i]->type();

            if ( t->type()->isReferenceType() && (style & CoercionStyle::TryDeref) )
                t = t->type()->dereferencedType();

            if ( t->isConstant() ) {
                HILTI_DEBUG(logging::debug::Coercer, util::fmt("  [param %d] need mutable expression -> failure", i));
                return result::Error("parameter requires non-constant expression");
            }
        }

        CoercedExpression result;

        if ( kind == operator_::Kind::Call && i == 0 && exprs[0]->isA<expression::Name>() &&
             ! exprs[0]->isResolved() ) {
            // Special case: For function calls, this expression will not have
            // been resolved by the resolver because it might not unambiguously
            // refer to just a single declaration (overloading, hooks).
            // However, the resolver will have ensured a name match with all
            // the candidates, so we can just accept it.
            result.coerced = exprs[i];
        }
        else
            result = coerceExpression(builder, exprs[i], oat, style);

        if ( ! result ) {
            HILTI_DEBUG(logging::debug::Coercer,
                        util::fmt("  [param %d] matching %s against %s -> failure [%s vs %s]", i, *exprs[i]->type(),
                                  *oat, exprs[i]->type()->type()->unification().str(),
                                  oat->type()->unification().str()));
            return result::Error("could not match coercion operands");
        }

        HILTI_DEBUG(logging::debug::Coercer,
                    util::fmt("  [param %d] matching %s against %s -> success: %s (coerced expression is %s) (%s)", i,
                              *exprs[i]->type(), *oat, *(*result.coerced)->type(),
                              ((*result.coerced)->type()->isConstant() ? "const" : "non-const"),
                              (result.consider_type_changed ? "type changed" : "type not changed")));

        // We check if the primary type of the alternative has changed. Only
        // one operand must change its primary type for an alternative to
        // match.
        if ( result.consider_type_changed && (++num_type_changes > 1 || style & CoercionStyle::DisallowTypeChanges) &&
             ! (style & CoercionStyle::FunctionCall) )
            return result::Error("no valid coercion found");

        if ( needs_mutable && result.nexpr && ! oat->type()->isWildcard() && ! oat->type()->isReferenceType() ) {
            auto* new_t = result.nexpr->type()->type();
            auto* orig_t = exprs[i]->type()->type();

            if ( orig_t->isReferenceType() )
                orig_t = orig_t->dereferencedType()->type();

            if ( ! type::same(orig_t, new_t) )
                return result::Error("parameter requires exact type match");
        }

        transformed.emplace_back(*result.coerced);

        if ( result.nexpr )
            changed = true;
    }

    return std::make_pair(changed, std::move(transformed));
}


// If an expression is a reference, dereference it; otherwise return the
// expression itself.
static Expression* skipReferenceValue(Builder* builder, Expression* op) {
    static const auto* value_reference_deref = operator_::get("value_reference::Deref");
    static const auto* strong_reference_deref = operator_::get("strong_reference::Deref");
    static const auto* weak_reference_deref = operator_::get("weak_reference::Deref");

    if ( ! op->type()->type()->isReferenceType() )
        return op;

    operator_::reference::DerefBase* deref = nullptr;

    if ( op->type()->type()->isA<type::ValueReference>() )
        deref = static_cast<operator_::reference::DerefBase*>(
            *value_reference_deref->instantiate(builder, {op}, op->meta()));
    else if ( op->type()->type()->isA<type::StrongReference>() )
        deref = static_cast<operator_::reference::DerefBase*>(
            *strong_reference_deref->instantiate(builder, {op}, op->meta()));
    else if ( op->type()->type()->isA<type::WeakReference>() )
        deref = static_cast<operator_::reference::DerefBase*>(
            *weak_reference_deref->instantiate(builder, {op}, op->meta()));
    else
        logger().internalError("unknown reference type");

    deref->setIsAutomaticCoercion(true);
    return deref;
}

static CoercedExpression coerceExpressionBackend(Builder* builder, Expression* e, QualifiedType* src_,
                                                 QualifiedType* dst_, bitmask<CoercionStyle> style, bool lhs) {
    const auto& no_change = e;
    CoercedExpression _result;
    int _line = 0;

#define RETURN(x)                                                                                                      \
    {                                                                                                                  \
        _result = (x);                                                                                                 \
        _line = __LINE__;                                                                                              \
        goto exit;                                                                                                     \
    }

    auto* src = src_;

    if ( auto* name = src->type()->tryAs<type::Name>() ) {
        if ( auto* d = name->resolvedDeclaration() )
            src = d->type();
        else
            return result::Error("type name has not been resolved");
    }

    auto* dst = dst_;

    if ( auto* name = dst->type()->tryAs<type::Name>() ) {
        if ( auto* d = name->resolvedDeclaration() )
            dst = d->type();
        else
            return result::Error("type name has not been resolved");
    }

    bool try_coercion = false;

    if ( dst->type()->isA<type::Auto>() )
        // Always accept, we're going to update the auto type later.
        RETURN(no_change);

    if ( src->type()->cxxID() && dst->type()->cxxID() ) {
        if ( src->type()->cxxID() == dst->type()->cxxID() ) {
            RETURN(no_change);
        }
    }

    if ( style & CoercionStyle::TryExactMatch ) {
        if ( type::same(src, dst) )
            RETURN(no_change);
    }

    if ( style & CoercionStyle::TryConstPromotion ) {
        if ( type::sameExceptForConstness(src, dst) )
            RETURN(no_change);

        if ( style & CoercionStyle::Assignment ) {
            if ( type::sameExceptForConstness(src, dst) )
                RETURN(no_change);

            if ( dst->type()->isWildcard() && src->type()->typeClass() == dst->type()->typeClass() )
                RETURN(no_change);
        }
    }

    if ( (style & CoercionStyle::TryDeref) &&
         ! (style & (CoercionStyle::DisallowTypeChanges | CoercionStyle::Assignment)) ) {
        if ( src->type()->isReferenceType() ) {
            auto* nsrc = src->type()->dereferencedType();
            if ( type::same(nsrc, dst) )
                RETURN(CoercedExpression(src_, skipReferenceValue(builder, e)));

            if ( style & CoercionStyle::TryConstPromotion ) {
                if ( type::sameExceptForConstness(nsrc, dst) )
                    RETURN(CoercedExpression(src_, skipReferenceValue(builder, e)));
            }
        }
    }

    if ( dst->type()->isA<type::Any>() )
        // type::Any accepts anything without actual coercion.
        RETURN(no_change);

    if ( auto* x = e->tryAs<expression::Member>() ) {
        // Make sure the expression remains a member expression, as we will
        // be expecting to cast it to that.
        if ( auto t = hilti::coerceType(builder, x->type(), dst_, style) ) {
            RETURN(CoercedExpression(src_, builder->expressionMember(*t, x->id(), x->meta())));
        }
        else
            RETURN(result::Error());
    }

    if ( auto* o = dst->type()->template tryAs<type::OperandList>() ) {
        // Match tuple against operands according to function call rules.
        HILTI_DEBUG(logging::debug::Coercer, util::fmt("matching against call parameters"));
        logging::DebugPushIndent _(logging::debug::Coercer);

        auto* c = e->template tryAs<expression::Ctor>();
        if ( ! c )
            RETURN(CoercedExpression());

        if ( auto* t = c->ctor()->template tryAs<hilti::ctor::Tuple>() ) {
            // The two style options both implicitly set CoercionStyle::FunctionCall.
            CoercionStyle function_style =
                (style & CoercionStyle::TryCoercion ? CoercionStyle::TryAllForFunctionCall :
                                                      CoercionStyle::TryDirectMatchForFunctionCall);
            if ( auto result =
                     coerceOperands(builder, operator_::Kind::Call, t->value(), o->operands(), function_style) ) {
                if ( result->first ) {
                    RETURN(CoercedExpression(e->type(), builder->expressionCtor(builder->ctorTuple(result->second))));
                }
                else
                    RETURN(no_change);
            }
        }

        RETURN(CoercedExpression());
    }

    if ( style & (CoercionStyle::Assignment | CoercionStyle::FunctionCall) ) {
        if ( auto* opt = dst->type()->tryAs<type::Optional>() ) {
            if ( opt->isWildcard() )
                RETURN(no_change);

            // All types converts into a corresponding optional.
            if ( auto x = coerceExpression(builder, e, opt->dereferencedType(), style) )
                RETURN(CoercedExpression(src_, builder->expressionCoerced(*x.coerced, dst_, e->meta())));
        }

        if ( auto* result = dst->type()->tryAs<type::Result>() ) {
            if ( result->isWildcard() )
                RETURN(no_change);

            // All types convert into a corresponding result.
            if ( auto x = coerceExpression(builder, e, result->dereferencedType(), style) )
                RETURN(CoercedExpression(src_, builder->expressionCoerced(*x.coerced, dst_, e->meta())));
        }

        if ( auto* x = dst->type()->tryAs<type::ValueReference>(); x && ! src->type()->isReferenceType() ) {
            // All types converts into a corresponding value_ref.
            if ( auto y = coerceExpression(builder, e, x->dereferencedType(), style) )
                RETURN(CoercedExpression(src_, builder->expressionCoerced(*y.coerced, dst_, e->meta())));
        }
    }

    if ( style & CoercionStyle::TryCoercion )
        try_coercion = true;

    if ( style & CoercionStyle::TryCoercionWithinSameType ) {
        if ( src->type()->typeClass() == dst->type()->typeClass() )
            try_coercion = true;
    }

    if ( try_coercion ) {
        if ( auto* c = e->tryAs<expression::Ctor>() ) {
            if ( auto nc = hilti::coerceCtor(builder, c->ctor(), dst, style) )
                RETURN(CoercedExpression(src_, builder->expressionCtor(builder->ctorCoerced(c->ctor(), *nc, c->meta()),
                                                                       e->meta())));
        }

        if ( auto t = hilti::coerceType(builder, src_, dst_, style) )
            // We wrap the expression into a coercion even if the new type is
            // the same as *dst*. That way the overloader has a way to
            // recognize that the types aren't identical.
            RETURN(CoercedExpression(src_, builder->expressionCoerced(e, *t, e->meta())));
    }

    _result = result::Error();

exit:
    if ( logger().isEnabled(logging::debug::Coercer) )
        HILTI_DEBUG(logging::debug::Coercer,
                    util::fmt("coercing %s (%s) to %s (%s) -> %s [%s] (%s) (#%d)", *src,
                              util::replace(src->type()->unification(), "hilti::type::", ""), *dst,
                              util::replace(dst->type()->unification(), "hilti::type::", ""),
                              (_result ? util::fmt("%s (%s)", *(*_result.coerced)->type(),
                                                   util::replace((*_result.coerced)->type()->type()->unification(),
                                                                 "hilti::type::", "")) :
                                         "fail"),
                              to_string(style), e->meta().location(), _line));

#undef RETURN

    return _result;
}

// Public version going through all plugins.
CoercedExpression hilti::coerceExpression(Builder* builder, Expression* e, QualifiedType* src, QualifiedType* dst,
                                          bitmask<CoercionStyle> style, bool lhs) {
    return coerceExpressionBackend(builder, e, src, dst, style, lhs);
}

// Public version going through all plugins.
CoercedExpression hilti::coerceExpression(Builder* builder, Expression* e, QualifiedType* dst,
                                          bitmask<CoercionStyle> style, bool lhs) {
    return coerceExpressionBackend(builder, e, e->type(), dst, style, lhs);
}

// Plugin-specific version just kicking off the local visitor.
Ctor* hilti::coercer::detail::coerceCtor(Builder* builder, Ctor* c, QualifiedType* dst, bitmask<CoercionStyle> style) {
    util::timing::Collector _("hilti/compiler/ast/coercer");

    if ( ! (c->type()->isResolved() && dst->isResolved()) )
        return {};

    auto v = VisitorCtor(builder, dst, style);
    v.dispatch(c);
    return v.result;
}

// Plugin-specific version just kicking off the local visitor.
QualifiedType* coercer::detail::coerceType(Builder* builder, QualifiedType* t, QualifiedType* dst,
                                           bitmask<CoercionStyle> style) {
    util::timing::Collector _("hilti/compiler/ast/coercer");

    if ( ! (t->isResolved() && dst->isResolved()) )
        return {};

    auto v = VisitorType(builder, t, dst, style);
    v.dispatch(t->type());
    return v.result;
}
