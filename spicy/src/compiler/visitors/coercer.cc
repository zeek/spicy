// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/base/logger.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace {

struct VisitorCtor : public hilti::visitor::PreOrder<std::optional<hilti::Ctor>, VisitorCtor> {
    VisitorCtor(const Type& dst, bitmask<hilti::CoercionStyle> style) : dst(dst), style(style) {}
    const hilti::Type& dst;
    bitmask<hilti::CoercionStyle> style;
};

struct VisitorType : public hilti::visitor::PreOrder<std::optional<hilti::Type>, VisitorType> {
    VisitorType(const Type& dst, bitmask<hilti::CoercionStyle> style) : dst(dst), style(style) {}
    const hilti::Type& dst;
    bitmask<hilti::CoercionStyle> style;
};

} // anonymous namespace

std::optional<hilti::Ctor> detail::coerceCtor(hilti::Ctor c, const hilti::Type& dst,
                                              bitmask<hilti::CoercionStyle> style) {
    if ( auto nc = VisitorCtor(dst, style).dispatch(std::move(c)) )
        return *nc;

    return {};
}

std::optional<Type> detail::coerceType(hilti::Type t, const hilti::Type& dst, bitmask<hilti::CoercionStyle> style) {
    if ( auto nt = VisitorType(dst, style).dispatch(std::move(t)) )
        return *nt;

    return {};
}
