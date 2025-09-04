// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cassert>
#include <string>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/reference.h>

namespace spicy::rt {

/**
 * Exception thrown on attempts to use a context not matching what the unit
 * expects.
 */
HILTI_EXCEPTION(ContextMismatch, UsageError)

/**
 * Type-erased wrapper around an instance of a parsing unit's `%context` type.
 *
 * This stores a reference to the instance, along with shallow copy semantics.
 * That means that units using copies of a particular instance of this class
 * will all share the same context.
 */
class UnitContext {
public:
    /**
     *
     * @tparam T type of the a unit's `%context`.
     * @param obj reference to a concrete context's instance
     * @param ti type information matching *obj*
     */
    template<typename T>
    UnitContext(hilti::rt::StrongReference<T> obj, const hilti::rt::TypeInfo* ti)
        : _object(std::move(obj)), _type_info(ti) {}
    /**
     * Returns the stored context instance, typed correctly.
     *
     * @tparam Context type of the context stored.
     * @param obj ti type information matching *Context*
     */
    template<typename Context>
    hilti::rt::StrongReference<Context> as(const hilti::rt::TypeInfo* ti) const {
        if ( ti != _type_info )
            throw ContextMismatch(hilti::rt::fmt("context mismatch between related units: expected %s, but got %s",
                                                 _type_info->display, ti->display));

        return hilti::rt::any_cast<hilti::rt::StrongReference<Context>>(_object);
    }

    UnitContext() = delete;
    UnitContext(const UnitContext&) = default;
    UnitContext(UnitContext&&) = default;

    UnitContext& operator=(const UnitContext&) = default;
    UnitContext& operator=(UnitContext&&) = default;

    virtual ~UnitContext(); // trigger vtable
private:
    hilti::rt::any _object;
    const hilti::rt::TypeInfo* _type_info;
};

namespace detail {

/**
 * Helper function to instantiate a new instance of a unit's `%context` type.
 *
 * @tparam Context the type of the `Context` instance
 * @param ti Type information matching `tparam`.
 */
template<typename Context>
inline UnitContext createContext(Context ctx, const hilti::rt::TypeInfo* ti) {
    if ( ti->tag == hilti::rt::TypeInfo::Tag::StrongReference )
        ti = ti->strong_reference->valueType();

    return UnitContext(std::move(ctx), ti);
}

/**
 * Helper function to set the internal ``__context`` member of a parser's unit type.
 *
 * @tparam Context the type of the target unit's `%context`
 * @param context writable reference to the target unit's ``__context`` field.
 * @param new_ctx the new context instance to set *context* to
 * @param ti Type information matching *Context*; it must be the same as what `new_ctx` carries, otherwise an exception
 * will be thrown
 */
template<typename Context>
inline void setContext(hilti::rt::StrongReference<Context>& context, const hilti::rt::TypeInfo* context_type,
                       const hilti::rt::Optional<UnitContext>& new_ctx, const hilti::rt::TypeInfo* ti) {
    if ( new_ctx )
        context = new_ctx->as<Context>(ti);
    else
        context = nullptr;
}

} // namespace detail

} // namespace spicy::rt

namespace hilti::rt::detail::adl {

inline std::string to_string(const spicy::rt::UnitContext& ctx, rt::detail::adl::tag /*unused*/) {
    return "<unit context>";
}

} // namespace hilti::rt::detail::adl
