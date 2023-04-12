// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/util.h>

namespace hilti::rt {

namespace trait {
struct isUnion {};
} // namespace trait

namespace union_ {
namespace detail {

/** Proxy object to facilitate assignment to a specific variant slot. */
template<int I, typename U>
class AssignProxy {
public:
    AssignProxy(U* u) : _u(u) {}

    template<typename T>
    AssignProxy& operator=(const T& t) {
        _u->value.template emplace<I>(t);
        return *this;
    }

    template<typename T>
    AssignProxy& operator=(T&& t) {
        _u->value.template emplace<I>(std::forward<T>(t));
        return *this;
    }

private:
    U* _u;
};

} // namespace detail

template<int I, class T>
inline auto& get(const T& u) {
    try {
        return std::get<I>(u.value);
    } catch ( const std::bad_variant_access& ) {
        throw UnsetUnionMember("access to union member that does not hold value");
    }
}

template<int I, class U>
inline auto get_proxy(U& u) {
    return detail::AssignProxy<I, U>(&u);
}

} // namespace union_

template<typename... T>
class Union : public trait::isUnion {
public:
    Union() = default;
    ~Union() = default;
    Union(const Union&) = default;
    Union(Union&&) noexcept = default;
    Union& operator=(const Union&) = default;
    Union& operator=(Union&&) noexcept = default;

    template<typename F>
    Union(const F& t) : value(t){};
    template<typename F>
    Union(const F&& t) : value(t){};
    template<typename F>
    Union& operator=(const F& t) {
        value = t;
        return *this;
    }

    template<typename F>
    Union& operator=(F&& t) {
        value = std::forward<F>(t);
        return *this;
    }

    /**
     * Returns the index of the value the variant holds. Because we always
     * use `std::monostate` as the first type, this will return a value
     * greater zero iff a value is set.
     */
    auto index() const { return value.index(); }

    std::variant<std::monostate, T...> value;
};

namespace detail::adl {
template<typename T, typename std::enable_if_t<std::is_base_of<trait::isUnion, T>::value>* = nullptr>
inline std::string to_string(const T& x, adl::tag /*unused*/) {
    std::string field = "<unset>";

    auto render_one = [&](auto k, auto v) {
        if ( v )
            field = fmt("$%s=%s", k, hilti::rt::to_string(*v));
    };

    x.__visit(render_one);
    return field;
}

} // namespace detail::adl

} // namespace hilti::rt
