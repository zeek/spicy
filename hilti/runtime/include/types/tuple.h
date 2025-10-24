// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <compare>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

#include <hilti/rt/configuration.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

template<typename T>
class ValueReference;

namespace tuple {
namespace detail {
// Helper to throw `UnsetTupleElement`. Outsourcing this helps the compiler
// optimize better.
__attribute__((noreturn)) void throw_unset_tuple_element();

// Tag type to indicate to tuple base class constructor that all elements are set.
struct AllSetTag {};
} // namespace detail

// Tag type to indicate to tuple constructor that elements may be unset.
struct OptionalTag {};

// Tag type to indicate to tuple constructor all elements are set.
struct ValueTag {};

namespace detail {
// Helper to detect a ValueReference type.
template<typename T>
struct IsValueReference : std::false_type {};

template<typename T>
struct IsValueReference<ValueReference<T>> : std::true_type {
    using element_type = T;
};
} // namespace detail
} // namespace tuple

/**
 * Common base class to all tuple types. The base class provides a public
 * function to check if a particular element is set, meaning that one can test
 * this generically without knowing the actual tuple element types.
 *
 * Internally, the base class performs the state management tracking which
 * elements are set through a bitmask.
 *
 * For efficiency, we currently limit the maximum number of tuple elements to
 * 64. This could be changed if deemed necessary.
 */
class TupleBase {
public:
    /**
     * Returns true if the element at index `idx` is set. If `idx` is
     * beyond the number of valid tuple elements the result is undefined.
     */
    constexpr bool hasValue(size_t idx) const { return idx < MaxElements ? (_mask & (1ULL << idx)) != 0 : false; }

    friend auto operator<=>(const TupleBase& t1, const TupleBase& t2) = default;

protected:
    /** Maximum number of tuple elements supported. */
    static constexpr size_t MaxElements = 64;

    /** Constructor marking all elements as initially unset. */
    TupleBase() = default;

    /**
     * Constructor marking all elements as initially set.
     *
     * @param tag tag to select this constructor
     * @param num_elements number of elements in the tuple
     */
    TupleBase(tuple::detail::AllSetTag, uint64_t num_elements) : _mask((1ULL << num_elements) - 1) {}

    TupleBase(const TupleBase& other) = default;
    TupleBase(TupleBase&& other) = default;
    ~TupleBase() = default;

    /**
     * Mark a specific element as set.
     *
     * @param idx index of the element to mark as set
     */
    void set(size_t idx) { _mask |= (1ULL << idx); }

    TupleBase& operator=(const TupleBase& other) = default;
    TupleBase& operator=(TupleBase&& other) = default;

private:
    uint64_t _mask = 0;
};

/**
 * Runtime representation of HILTI's `tuple` type. Different from `std::tuple`,
 * tuple elements can remain unset. If an unset element is accessed, an
 * `UnsetTupleElement` exception is thrown.
 *
 * For efficiency, we currently limit the maximum number of tuple elements to
 * 64. This could be changed if deemed necessary.

 * @tparam Ts types of the tuple elements
 **/
template<typename... Ts>
class Tuple : public TupleBase, protected std::tuple<Ts...> {
public:
    using Base = std::tuple<Ts...>;
    static_assert(sizeof...(Ts) <= MaxElements, "tuples with more than 64 elements are not supported");

    /** Default constructor creating an empty tuple with all elements unset. */
    Tuple() : Base(_defaultStorage()) {}

    /**
     * Constructor creating a tuple from provided values, with all elements
     * set.
     *
     * @param tag tag to select this constructor
     * @param us values for the tuple elements
     */
    template<typename... Us>
    explicit Tuple(tuple::ValueTag, Us&&... us)
        : TupleBase(tuple::detail::AllSetTag{}, sizeof...(Ts)), Base(std::forward<Us>(us)...) {}

    /**
     * Constructor creating a tuple from provided values, with some elements
     * potentially left unset.
     *
     * @param tag tag to select this constructor
     *
     * @param us values for the tuple elements wrapped into optionals, with
     * unset optionals leaving the corresponding tuple element unset
     */
    template<typename... Us>
    explicit Tuple(tuple::OptionalTag, Optional<Us>&&... us) : Tuple() {
        [&]<size_t... Is>(std::index_sequence<Is...>) {
            ((us.hasValue() ? std::get<Is>(*this) = std::forward<Us>(*us), TupleBase::set(Is) : void()), ...);
        }(std::index_sequence_for<Ts...>{});
    }

    /** Copy constructor. */
    Tuple(const Tuple& other) = default;

    /** Move constructor. */
    Tuple(Tuple&& other) = default;

    /**
     * Move constructor from another tuple type having elements of types that
     * convert to ours.
     */
    template<typename... Us>
    Tuple(Tuple<Us...>&& other) : TupleBase(other), Base(std::forward<typename std::tuple<Us...>>(other)) {}

    /**
     * Accessor to retrieve a particular element, assuming it's set.
     *
     * @tparam Idx index of the element to retrieve
     * @return reference to the element at index `Idx`
     * @throws `UnsetTupleElement` if the element at index `Idx` is not set
     */
    template<std::size_t Idx>
    const auto& get() const {
        if ( TupleBase::hasValue(Idx) )
            return std::get<Idx>(*this);
        else
            tuple::detail::throw_unset_tuple_element();
    }

    /**
     * Accessor to retrieve a particular element, assuming it's set.
     *
     * @tparam Idx index of the element to retrieve
     * @return reference to the element at index `Idx`
     * @throws `UnsetTupleElement` if the element at index `Idx` is not set
     */
    template<std::size_t Idx>
    auto& get() {
        if ( TupleBase::hasValue(Idx) )
            return std::get<Idx>(*this);
        else
            tuple::detail::throw_unset_tuple_element();
    }

    /**
     * Returns the binary offset of a particular element inside the tuple's
     * storage. The offset refers is to the start of the tuple.
     *
     * @tparam Idx index of the element to return
     */
    template<std::size_t Idx>
    static ptrdiff_t elementOffset() {
        Tuple t;
        // This is pretty certainly not well-defined, but seems to work for us ...
        // NOLINTNEXTLINE(clang-analyzer-security.PointerSub)
        return (reinterpret_cast<const char*>(&std::get<Idx>(t)) - reinterpret_cast<const char*>(&t));
    }

    Tuple& operator=(const Tuple& other) = default;
    Tuple& operator=(Tuple&& other) = default;

    template<typename... Us>
    friend std::weak_ordering operator<=>(const Tuple<Ts...>& t1, const Tuple<Us...>& t2) {
        return static_cast<const Base&>(t1) <=> static_cast<const Base&>(t2);
    }

private:
    template<typename... Us>
    friend class Tuple;

    // This returns the value that we initialize the storage tuple with when no
    // fields are set. That's mostly just the elements' defaults, except for
    // ValueReference types, which we initialize with a nullptr. The latter
    // lets us deal with self-recursive tuple types.
    static auto _defaultStorage() {
        return Base{[]() {
            if constexpr ( tuple::detail::IsValueReference<Ts>::value ) {
                using element_type = typename tuple::detail::IsValueReference<Ts>::element_type;
                return Ts(std::shared_ptr<element_type>(nullptr));
            }
            else
                return Ts{};
        }()...};
    }
};

namespace tuple {

/**
 * Factory function to create a HILTI tuple from provided values, with all
 * elements of the resulting tuple set. This works like `std::make_tuple`.
 *
 * @tparam Ts types of the tuple elements
 * @param ts the tuple's elements
 */
template<typename... Ts>
constexpr auto make(Ts&&... ts) {
    return Tuple<std::decay_t<Ts>...>(tuple::ValueTag{}, std::forward<Ts>(ts)...);
}

/**
 * Factory function to create a HILTI tuple from provided values, with some
 * elements of the resulting tuple potentially left unset.
 *
 * @tparam Ts types of the tuple elements
 * @param ts the tuple's elements wrapped into optionals, with unset optionals
 * leaving the corresponding tuple element unset
 */
template<typename... Ts>
constexpr auto make_from_optionals(Optional<Ts>&&... ts) {
    return Tuple<std::decay_t<std::remove_reference_t<Ts>>...>(tuple::OptionalTag{}, std::move(ts)...);
}

/**
 * Returns a particular element of a tuple, assuming the element is set.
 *
 * @tparam Idx index of the element to check
 * @tparam Ts types of the tuple elements
 * @param t the tuple
 * @throws `UnsetTupleElement` if the element at index `Idx` is not set
 */
template<size_t Idx, typename... Ts>
const auto& get(const Tuple<Ts...>& t) {
    return t.template get<Idx>();
}

/**
 * Returns a particular element of a tuple, assuming the element is set.
 *
 * @tparam Idx index of the element to check
 * @tparam Ts types of the tuple elements
 * @param t the tuple
 * @throws `UnsetTupleElement` if the element at index `Idx` is not set
 */
template<size_t Idx, typename... Ts>
auto& get(Tuple<Ts...>& t) {
    return t.template get<Idx>();
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

/**
 * Assigns the values of a HILTI tuple to a standard tuple of references, with
 * the latter usually created through `std::tie()`. This  lets us support
 * `std::tie(...) = (...)`. It assumes all elements of the HILTI tuple are set.
 * If not all elements are set, throws an `UnsetTupleElement` exception.
 *
 * @tparam Ss source tuple of type `rt::Tuple`
 * @tparam Ts types of destination tuple elements
 * @param dst destination tuple of references
 * @param src source tuple
 */
template<typename Ss, typename... Ts>
constexpr void assign(std::tuple<Ts&...>&& dst, const Ss& src) {
    [&]<size_t... Is>(std::index_sequence<Is...> /*unused*/) {
        ((std::get<Is>(dst) = src.template get<Is>()), ...);
    }(std::index_sequence_for<Ts...>{});
}

/**
 * Helper for the code generator to wrap evaluation of an expression into a
 * catch-handler for `AttributeNotSet` (as thrown by `.?`).
 *
 * @param f A function evaluating the desired expression, returning the result.
 * @return An optional containing the result of the expression, or remaining
 * unset if the expression threw `AttributeNotSet` (all other exceptions are
 * passed through)
 */
template<typename Func>
auto wrap_expression(Func&& f) {
    using element_t = std::invoke_result_t<Func>;
    try {
        return Optional<element_t>(f());
    } catch ( const hilti::rt::AttributeNotSet& e ) {
        return Optional<element_t>();
    }
}

/** Corresponds to `hilti::printTuple`. */
template<typename... Ts>
void print(const Tuple<Ts...>& x, bool newline = true) {
    if ( ! configuration::get().cout )
        return;

    auto& cout = configuration::get().cout->get();

    std::vector<std::string> elems;
    [&]<std::size_t... Is>(std::index_sequence<Is...> /*unused*/) {
        (..., elems.push_back(x.hasValue(Is) ? rt::to_string_for_print(tuple::get<Is>(x)) : std::string("(not set)")));
    }(std::index_sequence_for<Ts...>{});

    cout << rt::join(elems, ", ");

    if ( newline )
        cout << '\n';
    else
        cout.flush();
}


} // namespace tuple

namespace detail::adl {
template<typename... Ts>
inline std::string to_string(const Tuple<Ts...>& x, adl::tag /*unused*/) {
    std::vector<std::string> elems;
    [&]<std::size_t... Is>(std::index_sequence<Is...> /*unused*/) {
        (..., elems.push_back(x.hasValue(Is) ? rt::to_string(tuple::get<Is>(x)) : std::string("(not set)")));
    }(std::index_sequence_for<Ts...>{});

    return fmt("(%s)", rt::join(elems, ", "));
}

} // namespace detail::adl
} // namespace hilti::rt

namespace std {
template<typename... Ts>
inline std::ostream& operator<<(std::ostream& out, const hilti::rt::Tuple<Ts...>& x) {
    out << hilti::rt::to_string_for_print(x);
    return out;
}

} // namespace std

// Add support for structured binding for Tuple.
template<typename... Ts>
struct std::tuple_size<hilti::rt::Tuple<Ts...>> : std::integral_constant<std::size_t, sizeof...(Ts)> {};

template<std::size_t I, typename... Ts>
struct std::tuple_element<I, hilti::rt::Tuple<Ts...>> {
    using type = std::tuple_element_t<I, std::tuple<Ts...>>;
};
