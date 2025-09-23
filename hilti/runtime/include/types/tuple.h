// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include <hilti/rt/configuration.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/optional.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

/**
 * Runtime representation of HILTI's `tuple` type. As tuple element can be left
 * unset, we wrap them into optionals.
 *
 * @tparam Ts types of the tuple elements
 **/
template<typename... Ts>
using Tuple = std::tuple<std::optional<Ts>...>;

namespace tuple {

namespace detail {
// Helper to throw `UnsetTupleElement`. Outsourcing this helps the compiler
// optimize better.
__attribute__((noreturn)) void throw_unset_tuple_element();
} // namespace detail

/**
 * Factory function to create a HILTI tuple with all elements set. This works
 * like `std::make_tuple`, but wraps all arguments into `std::optional` for
 * storage (i.e., don't pass the arguments already wrapped into
 * `std::optional`).
 *
 * @tparam Ts types of the tuple elements
 * @param ts the values to wrap into optionals
 */
template<typename... Ts>
constexpr auto make(Ts&&... ts) {
    return std::make_tuple(std::optional<std::remove_reference_t<Ts>>(std::move(ts))...);
}

/**
 * Factory function to create a HILTI tuple with from a list of values wrapped
 * into optionals. This allows leaving elements unset.
 *
 * @tparam Ts types of the tuple elements
 * @param ts the values wrap already wrapped into optionals
 */
template<typename... Ts>
constexpr auto make_from_optionals(std::optional<Ts>&&... ts) {
    return std::make_tuple(std::move(ts)...);
}

/**
 * Returns true if a particular element of a tuple is set.
 *
 * @tparam Idx index of the element to check
 * @tparam Ts types of the tuple elements
 * @param t the tuple
 */
template<size_t Idx, typename... Ts>
constexpr auto has_value(const Tuple<Ts...>& t) {
    return std::get<Idx>(t).has_value();
}

/**
 * Returns a particular element of a tuple. This assumes the element is set,
 * and returns a reference to the dereferenced optional wrapper. If the element
 * is not set, throws a `UnsetTupleElement` exception.
 *
 * @tparam Idx index of the element to check
 * @tparam Ts types of the tuple elements
 * @param t the tuple
 */
template<size_t Idx, typename... Ts>
const auto& get(const Tuple<Ts...>& t) {
    try {
        return std::get<Idx>(t).value();
    } catch ( ... ) {
        detail::throw_unset_tuple_element();
    }
}

/**
 * Returns a particular element of a tuple. This assumes the element is set,
 * and returns a reference to the dereferenced optional wrapper. If the element
 * is not set, throws a `UnsetTupleElement` exception.
 *
 * @tparam Idx index of the element to check
 * @tparam Ts types of the tuple elements
 * @param t the tuple
 */
template<size_t Idx, typename... Ts>
auto& get(Tuple<Ts...>& t) {
    try {
        return std::get<Idx>(t).value();
    } catch ( ... ) {
        detail::throw_unset_tuple_element();
    }
}

// Helper overload to allow `tuple::get()` to operate on a `std::pair`. Inside
// the runtime library, we sometimes use `std::pair` as a tuple with two
// elements, and this allows using the same `get()` with both. We do that for
// better performance in cases where we'd otherwise need to unnecessarily
// re-create a tuple from an already existing pair (e.g., with key/value pairs
// retrieved from maps).
template<size_t Idx, typename... Ts>
constexpr auto get(const std::pair<Ts...>& t) {
    return std::get<Idx>(t);
}

// Same as above.
template<size_t Idx, typename... Ts>
constexpr auto& get(std::pair<Ts...>& t) {
    return std::get<Idx>(t);
}

namespace detail {

template<typename Src, typename Dst, size_t... Is>
constexpr void assign(Dst&& dst, const Src& src, std::index_sequence<Is...> /*unused*/) {
    // Short-circuit here seems to be cheaper than possible SIMD execution with `||`.
    if ( auto some_unset = ! (std::get<Is>(src).has_value() && ...) )
        detail::throw_unset_tuple_element();

    ((std::get<Is>(std::forward<Dst>(dst)) = *std::get<Is>(src)), ...);
}

} // namespace detail

/**
 * Assigns the values of a HILTI tuple to a standard tuple of references, with
 * the latter usually created through `std::tie()`. This works like
 * `std::tie(...) = (...)`, but assigns the RHS values unwrapped from their
 * `std::optional` wrappers. This assumes all elements are set. If not all
 * elements are set, throws an `UnsetTupleElement` exception.
 *
 * @tparam Src source tuple of type `rt::Tuple`
 * @tparam Ts types of destination tuple elements
 * @param dst destination tuple of references
 * @param src source tuple
 */
template<typename Src, typename... Ts>
constexpr void assign(std::tuple<Ts&...>&& dst, const Src& src) {
    detail::assign(std::move(dst), src, std::index_sequence_for<Ts...>());
}

/**
 * Returns the binary offset of a particular element inside a tuple's storage.
 * The offset refers to the wrapping `std::optional` and is relative to the
 * start of the tuple.
 *
 * @tparam Tuple index of the element to check
 * @tparam Idx index of the element to check
 */
template<typename Tuple, size_t Idx>
ptrdiff_t elementOffset() {
    // This is pretty certainly not well-defined, but seems to work for us ...
    Tuple t; // requires all elements to be default constructable, which should be the case for us
    // NOLINTNEXTLINE(clang-analyzer-security.PointerSub)
    return reinterpret_cast<const char*>(&std::get<Idx>(t)) - reinterpret_cast<const char*>(&t);
}

/**
 * Helper for the code generator to wrap evaluation of an expression into a
 * catch-handler for `AttributeNotSet` (as thrown by `.?`).
 *
 * @param f A function evaluating the desired expression, returning the result.
 * @return An optional containing the result of the expression, or remaining
 * unset if the expression threw `AttributeNotSet` (all other exception are
 * passed through)
 */
template<typename Func>
auto wrap_expression(Func&& f) {
    using element_t = std::invoke_result_t<Func>;
    try {
        return std::optional<element_t>(f());
    } catch ( const hilti::rt::AttributeNotSet& e ) {
        return std::optional<element_t>();
    }
}

namespace detail {

// Helper joining a tuple into a string, using a `to_string_for_print()` on
// each element and adding a separator between elements.
template<typename T>
std::string join_to_string(T&& x, const std::string& separator) {
    std::stringstream out;

    if constexpr ( std::tuple_size_v<T> != 0 )
        std::apply(
            [&](auto& arg, auto&... args) {
                out << rt::to_string_for_print(arg);
                ((out << separator << rt::to_string_for_print(args)), ...);
            },
            x);

    return out.str();
}

} // namespace detail

/** Corresponds to `hilti::printTuple`. */
template<typename... Ts>
void print(const Tuple<Ts...>& x, bool newline = true) {
    if ( ! configuration::get().cout )
        return;

    auto& cout = configuration::get().cout->get();

    auto y = map_tuple(x, [](const auto& elem) {
        if ( elem )
            // Skip rendering the optional wrapper.
            return rt::to_string_for_print(*elem);
        else
            // Render the unset optional.
            return rt::to_string_for_print(elem);
    });

    cout << detail::join_to_string(std::move(y), ", ");

    if ( newline )
        cout << '\n';
    else
        cout.flush();
}


} // namespace tuple

namespace detail::adl {
template<typename... Ts>
inline std::string to_string(const Tuple<Ts...>& x, adl::tag /*unused*/) {
    auto y = rt::map_tuple(x, [](const auto& elem) {
        using elem_t = std::decay_t<decltype(elem)>;
        static_assert(std::is_same_v<elem_t, std::optional<typename elem_t::value_type>>,
                      "expected optional type for element");

        if ( elem )
            // Skip rendering the optional wrapper.
            return rt::to_string(*elem);
        else
            // Render the unset optional.
            return rt::to_string(elem);
    });

    return fmt("(%s)", tuple::detail::join_to_string(std::move(y), ", "));
}

// For convenience, we also provide string conversion for standard tuples. This
// is in particular used during unit testing.
template<typename... Ts>
inline std::string to_string(const std::tuple<Ts...>& x, adl::tag /*unused*/) {
    auto y = rt::map_tuple(x, [](const auto& e) { return hilti::rt::to_string(e); });
    return fmt("(%s)", tuple::detail::join_to_string(std::move(y), ", "));
}

} // namespace detail::adl
} // namespace hilti::rt

namespace std {

template<typename... Ts>
inline std::ostream& operator<<(std::ostream& out, const hilti::rt::Tuple<Ts...>& x) {
    out << hilti::rt::to_string_for_print(x);
    return out;
}

// For convenience, we also provide a `std::ostream` operator for standard
// tuples. This is in particular used during unit testing.
template<typename... Ts>
inline std::ostream& operator<<(std::ostream& out, const std::tuple<Ts...>& x) {
    return out << hilti::rt::to_string_for_print(x);
    return out;
}

} // namespace std
