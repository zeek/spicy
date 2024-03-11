// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/forward.h>
#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/coercer.h>

using namespace spicy;

namespace hilti::logging::debug {
inline const DebugStream Operator("operator");
} // namespace hilti::logging::debug


namespace {

struct VisitorCtor : visitor::PreOrder {
    VisitorCtor(Builder* builder, QualifiedType* dst, bitmask<hilti::CoercionStyle> style)
        : builder(builder), dst(dst), style(style) {}

    Builder* builder;
    QualifiedType* dst = nullptr;
    bitmask<hilti::CoercionStyle> style;

    Ctor* result = nullptr;

    void operator()(hilti::ctor::String* n) final {
        if ( auto x = dst->type()->tryAs<hilti::type::Library>(); x && x->cxxName() == "::spicy::rt::MIMEType" )
            result = builder->ctorLibrary(n, dst, n->meta());
    }

    void operator()(hilti::ctor::Tuple* n) final {
        if ( auto x = dst->type()->tryAs<hilti::type::Library>(); x && x->cxxName() == "::spicy::rt::ParserPort" )
            result = builder->ctorLibrary(n, dst, n->meta());
    }

    void operator()(hilti::ctor::Struct* n) final {
        if ( auto x = dst->type()->tryAs<spicy::type::Unit>(); x && x->typeID() ) {
            auto nc = builder->ctorUnit(n->fields(), n->meta());
            // We force the types to match for now, and let the HILTI struct
            // validator decide later if they are actually compatible.
            nc->setType(builder->context(),
                        builder->qualifiedType(builder->typeName(x->typeID()), hilti::Constness::Const));
            result = nc;
        }
    }
};

struct VisitorType : visitor::PreOrder {
    explicit VisitorType(Builder* builder, QualifiedType* dst, bitmask<hilti::CoercionStyle> style)
        : builder(builder), dst(dst), style(style) {}

    Builder* builder;
    QualifiedType* dst = nullptr;
    bitmask<hilti::CoercionStyle> style;

    QualifiedType* result = nullptr;

    void operator()(type::Unit* n) final {
        if ( auto x = dst->type()->tryAs<hilti::type::StrongReference>();
             x && hilti::type::same(x->dereferencedType()->type(), n) )
            // Our codegen will turn a unit T into value_ref<T>, which coerces to strong_ref<T>.
            result = dst;
    }
};

} // anonymous namespace


Ctor* spicy::detail::coercer::coerceCtor(Builder* builder, Ctor* c, QualifiedType* dst,
                                         bitmask<hilti::CoercionStyle> style) {
    hilti::util::timing::Collector _("spicy/compiler/ast/coercer");

    if ( ! (c->type()->isResolved() && dst->isResolved()) )
        return {};

    auto v = VisitorCtor(builder, dst, style);
    v.dispatch(c);

    if ( v.result )
        return v.result;
    else
        return (*hilti::plugin::registry().hiltiPlugin().coerce_ctor)(builder, c, dst, style);
}

QualifiedType* spicy::detail::coercer::coerceType(Builder* builder, QualifiedType* t, QualifiedType* dst,
                                                  bitmask<hilti::CoercionStyle> style) {
    hilti::util::timing::Collector _("spicy/compiler/ast/coercer");

    if ( ! (t->isResolved() && dst->isResolved()) )
        return {};

    auto v = VisitorType(builder, dst, style);
    v.dispatch(t->type());

    if ( v.result )
        return v.result;
    else
        return (*hilti::plugin::registry().hiltiPlugin().coerce_type)(builder, t, dst, style);
}
