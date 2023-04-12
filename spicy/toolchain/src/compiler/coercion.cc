// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/type.h>
#include <hilti/ast/ctors/library.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/reference.h>
#include <hilti/compiler/plugin.h>

#include <spicy/ast/ctors/unit.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit.h>
#include <spicy/compiler/detail/coercion.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace hilti::logging::debug {
inline const DebugStream Operator("operator");
} // namespace hilti::logging::debug


namespace {

struct VisitorCtor : public hilti::visitor::PreOrder<std::optional<Ctor>, VisitorCtor> {
    VisitorCtor(const Type& dst, bitmask<hilti::CoercionStyle> style) : dst(dst), style(style) {}

    const Type& dst;
    bitmask<hilti::CoercionStyle> style;

    result_t operator()(const hilti::ctor::String& c) {
        if ( auto x = dst.tryAs<hilti::type::Library>(); x && x->cxxName() == "::spicy::rt::MIMEType" )
            return hilti::ctor::Library(c, dst, c.meta());

        return {};
    }

    result_t operator()(const hilti::ctor::Tuple& c) {
        if ( auto x = dst.tryAs<hilti::type::Library>(); x && x->cxxName() == "::spicy::rt::ParserPort" )
            return hilti::ctor::Library(c, dst, c.meta());

        return {};
    }

    result_t operator()(const hilti::ctor::Struct& c) {
        if ( auto x = dst.tryAs<spicy::type::Unit>(); x && x->id() ) {
            auto nc = spicy::ctor::Unit(c.fields().copy(), c.meta());
            // We force the types to match for now, and let the HILTI struct
            // validator decide later if they are actually compatible.
            nc.setType(hilti::builder::typeByID(*x->id()));
            return nc;
        }

        return {};
    }
};

struct VisitorType : public hilti::visitor::PreOrder<std::optional<Type>, VisitorType> {
    VisitorType(const Type& dst, bitmask<hilti::CoercionStyle> style) : dst(dst), style(style) {}

    const Type& dst;
    bitmask<hilti::CoercionStyle> style;

    result_t operator()(const type::Unit& t, position_t p) {
        if ( auto x = dst.tryAs<type::StrongReference>(); x && x->dereferencedType() == p.node.as<Type>() )
            // Our codegen will turn a unit T into value_ref<T>, which coerces to strong_ref<T>.
            return dst;

        return {};
    }
};

} // anonymous namespace

// Plugin-specific version just kicking off the local visitor.
std::optional<Ctor> spicy::detail::coerceCtor(Ctor c, const Type& dst, bitmask<hilti::CoercionStyle> style) {
    if ( ! (type::isResolved(c.type()) && type::isResolved(dst)) )
        return {};

    if ( auto nc = VisitorCtor(dst, style).dispatch(c) )
        return *nc;

    return (*hilti::plugin::registry().hiltiPlugin().coerce_ctor)(std::move(c), dst, style);
}

// Plugin-specific version just kicking off the local visitor.
std::optional<Type> spicy::detail::coerceType(Type t, const Type& dst, bitmask<hilti::CoercionStyle> style) {
    if ( ! (type::isResolved(t) && type::isResolved(dst)) )
        return {};

    if ( auto nt = VisitorType(dst, style).dispatch(t) )
        return *nt;

    return (*hilti::plugin::registry().hiltiPlugin().coerce_type)(std::move(t), dst, style);
}
