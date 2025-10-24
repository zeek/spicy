// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/stream.h>

#include <spicy/rt/debug.h>
#include <spicy/rt/typedefs.h>

namespace spicy::rt::filter {
namespace detail {

/** Checks whether a given struct type corresponds to a Spicy filter unit. */
template<typename T, typename = int>
struct is_filter : std::false_type {};

template<typename T>
struct is_filter<T, decltype((void)T::__forward, 0)> : std::true_type {};

struct OneFilter {
    using Parse1Function = hilti::rt::Resumable (*)(const hilti::rt::StrongReferenceGeneric&,
                                                    hilti::rt::ValueReference<hilti::rt::Stream>&,
                                                    const hilti::rt::Optional<hilti::rt::stream::View>&);

    OneFilter() = default;
    OneFilter(OneFilter&&) = default;
    OneFilter(const OneFilter&) = delete;
    OneFilter(Parse1Function _parse, hilti::rt::StrongReferenceGeneric unit,
              hilti::rt::ValueReference<hilti::rt::Stream> _input, hilti::rt::Resumable _resumable)
        : parse(_parse), unit(std::move(unit)), input(std::move(_input)), resumable(std::move(_resumable)) {}

    Parse1Function parse = nullptr;
    hilti::rt::StrongReferenceGeneric unit;
    hilti::rt::ValueReference<hilti::rt::Stream> input;
    hilti::rt::Resumable resumable;
};

/**
 * State stored inside a unit instance to capture filters it has connected to itself.
 * it.
 */
using Filters = hilti::rt::Vector<OneFilter>;

/**
 * State stored inside a unit instance when it's filtering another one's
 * input. This is the data that `forward()` writes to.
 */
using Forward = hilti::rt::Stream;

} // namespace detail

/**
 * Type holding state for filter operations inside types that can either act as
 * filters or receive filtered input.
 *
 * \note The important thing for such types is that they offer these fields
 * themselves, although not necessarily through this actual type. In particular,
 * the unit structs that the Spicy code generator produces, include these fields
 * directly; they are not using this type. This type is meant primarily for the
 * runtime library when it needs to interface with filters (like sinks do).
 *
 * @tparam debug_type_name name used (only) in debug output to identify to the type
 *
 * \todo(robin): Can/should we switch generated unit types over to using this
 * struct as well?
 */
template<const char* debug_type_name>
struct State {
    /** List of connected filters. */
    hilti::rt::StrongReference<::spicy::rt::filter::detail::Filters> __filters;

    /** Destination for data being forwarded. */
    hilti::rt::WeakReference<::spicy::rt::filter::detail::Forward> __forward;

    /** Returns true if at least one filter has been connected. */
    operator bool() const { return __filters && (*__filters).size(); }

    /** Dummy struct capturing the type's name for debug purposes. */
    using _ParserDummy = struct {
        const char* name;
    };

    /** Pseudo-parser object. It just needs to have a `name`. */
    inline static _ParserDummy __parser = _ParserDummy{.name = debug_type_name};
};

template<const char* debug_type_name>
inline std::ostream& operator<<(std::ostream& out, State<debug_type_name>& s) {
    out << s.__parser.name;
    return out;
}

/**
 * Disconnects all connected filters from a unit. This is an internal method
 * for cleaning up at the end; it's not exposed as a method to users as it
 * would probably not being doing quite what's expected (because parsing
 * would continue to use the structure being set up).
 *
 * @tparam S type compatible with the attribute's defined by the `State` type.
 */
template<typename S>
void disconnect(S& state, const hilti::rt::TypeInfo* /* ti */) {
    if ( state.__filters ) {
        for ( auto& f : *state.__filters ) {
            SPICY_RT_DEBUG_VERBOSE(
                hilti::rt::fmt("- disconnecting existing filter unit from unit %s [%p]", S::__parser.name, &state));
            f.resumable.abort();
        }

        (*state.__filters).clear(); // Will invalidate the targets' output
    }

    if constexpr ( detail::is_filter<S>::value ) {
        if ( state.__forward ) {
            SPICY_RT_DEBUG_VERBOSE(hilti::rt::fmt("- sending EOD from filter unit %s [%p] to stream %p on disconnect",
                                                  S::__parser.name, &state, state.__forward.get()));
            (*state.__forward).freeze();
        }
    }
}

template<typename U>
void disconnect(UnitType<U>& unit, const hilti::rt::TypeInfo* ti) {
    return disconnect(*unit, ti);
}

namespace detail {
// Internal backend of connect(), see below, that doesn't require the type info
// (which we don't need anyways).
template<typename S, typename F>
void connect(S& state, UnitRef<F> filter_unit) {
    SPICY_RT_DEBUG_VERBOSE(hilti::rt::fmt("- connecting filter unit %s [%p] to unit %s [%p]", F::__parser.name,
                                          &*filter_unit, S::__parser.name, &state));

    if ( ! state.__filters )
        state.__filters = hilti::rt::reference::make_strong<::spicy::rt::filter::detail::Filters>();

    auto filter =
        detail::OneFilter{[](const hilti::rt::StrongReferenceGeneric& filter_unit,
                             hilti::rt::ValueReference<hilti::rt::Stream>& data,
                             const hilti::rt::Optional<hilti::rt::stream::View>& cur) -> hilti::rt::Resumable {
                              auto lhs_filter_unit = filter_unit.derefAsValue<F>();
                              auto parse2 = hilti::rt::any_cast<Parse2Function<F>>(F::__parser.parse2);
                              SPICY_RT_DEBUG_VERBOSE(
                                  hilti::rt::fmt("  + parsing from stream %p, forwarding to stream %p", data.get(),
                                                 lhs_filter_unit->__forward.get()));
                              return (*parse2)(lhs_filter_unit, data, cur, {});
                          },
                          filter_unit,
                          hilti::rt::Stream(),
                          {}};

    (*state.__filters).push_back(std::move(filter));
    filter_unit->__forward = (*state.__filters).back().input;
}

} // namespace detail

/**
 * Connects a filter unit to a unit for transforming parsing. This won't have
 * an observable effect until `filter::init()` is executed (and must be called
 * before that).
 *
 * @tparam S type compatible with the attribute's defined by the `State`
 * type; this is target unit being connected to
 *
 * @tparam F type likewise compatible with `State; this the filter unit
 * doing the transformation
 */
template<typename S, typename F>
void connect(S& state, const hilti::rt::TypeInfo* ti, UnitRef<F> filter_unit) {
    detail::connect(state, filter_unit);
}

template<typename U, typename F>
void connect(UnitType<U>& unit, const hilti::rt::TypeInfo* ti, UnitRef<F> filter_unit) {
    detail::connect(*unit, filter_unit);
}

/**
 * Set up filtering for a unit if any filters have been connected. Must be
 * called before parsing starts.
 *
 * @tparam S type compatible with the attribute's defined by the `State` type.
 */
template<typename S>
hilti::rt::StrongReference<hilti::rt::Stream> init(
    S& state, // NOLINT(google-runtime-references)
    const hilti::rt::TypeInfo* /* ti */,
    hilti::rt::ValueReference<hilti::rt::Stream>& data, // NOLINT(google-runtime-references)
    const hilti::rt::stream::View& cur) {
    if ( ! (state.__filters && (*state.__filters).size()) )
        return {};

    detail::OneFilter* previous = nullptr;

    for ( auto& f : *state.__filters ) {
        SPICY_RT_DEBUG_VERBOSE(
            hilti::rt::fmt("- beginning to filter input for unit %s [%p]", S::__parser.name, &state));

        if ( ! previous )
            f.resumable = f.parse(f.unit, data, cur);
        else
            f.resumable = f.parse(f.unit, previous->input, previous->input->view());

        previous = &f;
    }

    return hilti::rt::StrongReference<hilti::rt::Stream>((*state.__filters).back().input);
}

template<typename U>
hilti::rt::StrongReference<hilti::rt::Stream> init(
    UnitType<U>& unit, // NOLINT(google-runtime-references)
    const hilti::rt::TypeInfo* ti,
    hilti::rt::ValueReference<hilti::rt::Stream>& data, // NOLINT(google-runtime-references)
    const hilti::rt::stream::View& cur) {
    return init(*unit, ti, data, cur);
}

/**
 * Forward data from a filter unit to the unit it's connected to. A noop if
 * the unit isn't connected as a filter to anything.
 *
 * @tparam S type compatible with the attribute's defined by the `State` type.
 */
template<typename S>
inline void forward(S& state, const hilti::rt::TypeInfo* /* ti */, const hilti::rt::Bytes& data) {
    if ( ! state.__forward ) {
        SPICY_RT_DEBUG_VERBOSE(
            hilti::rt::fmt("- filter unit %s [%p] is forwarding \"%s\", but not connected to any unit",
                           S::__parser.name, &state, data));
        return;
    }

    SPICY_RT_DEBUG_VERBOSE(hilti::rt::fmt("- filter unit %s [%p] is forwarding \"%s\" to stream %p", S::__parser.name,
                                          &state, data, state.__forward.get()));
    state.__forward->append(data);
}

template<typename U>
inline void forward(UnitType<U>& unit, const hilti::rt::TypeInfo* ti, const hilti::rt::Bytes& data) {
    return forward(*unit, ti, data);
}

/**
 * Signals EOD from a filter unit to the unit it's connected to. A noop if
 * the unit isn't connected as a filter to anything.
 *
 * @tparam S type compatible with the attribute's defined by the `State` type.
 */
template<typename S>
inline void forward_eod(S& state, const hilti::rt::TypeInfo* /* ti */) {
    if ( ! state.__forward ) {
        SPICY_RT_DEBUG_VERBOSE(hilti::rt::fmt("- filter unit %s [%p] is forwarding EOD, but not connected to any unit",
                                              S::__parser.name, &state));
        return;
    }

    SPICY_RT_DEBUG_VERBOSE(hilti::rt::fmt("- filter unit %s [%p] is forwarding EOD to stream %p", S::__parser.name,
                                          &state, state.__forward.get()));
    state.__forward->freeze();
}

template<typename U>
inline void forward_eod(UnitType<U>& unit, const hilti::rt::TypeInfo* ti) {
    return forward_eod(*unit, ti);
}

/**
 * Lets all filters in a list process as much of their pending input as
 * possible. This should be called after new data has been appended to their
 * input stream.
 */
inline void flush(hilti::rt::StrongReference<spicy::rt::filter::detail::Filters> filters) {
    for ( auto& f : (*filters) )
        f.resumable.resume();
}

/**
 * Lets all filters process as much of their pending input as possible. This
 * should be called after new data has been appended to theor input stream.
 *
 * @tparam S type compatible with the attribute's defined by the `State` type.
 */
template<typename S>
inline void flush(S& state, const hilti::rt::TypeInfo* /* ti */) {
    flush(state.__filters);
}

template<typename U>
inline void flush(UnitType<U>& unit, const hilti::rt::TypeInfo* ti) {
    flush(*unit, ti);
}

} // namespace spicy::rt::filter

namespace hilti::rt::detail::adl {
inline std::string to_string(const spicy::rt::filter::detail::OneFilter& u, adl::tag /*unused*/) { return "<filter>"; };
} // namespace hilti::rt::detail::adl

namespace spicy::rt {
inline std::ostream& operator<<(std::ostream& out, const filter::detail::OneFilter& u) {
    return out << hilti::rt::to_string(u);
}
} // namespace spicy::rt
