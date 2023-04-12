// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <functional>
#include <string>
#include <utility>

#include <hilti/rt/extension-points.h>
#include <hilti/rt/types/result.h>

namespace hilti::rt {

/**
 * Wrapper for an expression that's evaluation is deferred until requested.
 * The expression must be wrapped into a function call, and it's evaluation
 * is requested through the wrapper's call operator.
 *
 * The function should be stateless as it might be invoked an unspecified
 * number of times.
 */
template<typename Result>
class DeferredExpression {
public:
    DeferredExpression(std::function<Result()> expr) : _expr(std::move(expr)) {}
    DeferredExpression() = delete;
    DeferredExpression(const DeferredExpression&) = default;
    DeferredExpression(DeferredExpression&&) noexcept = default;

    ~DeferredExpression() = default;

    DeferredExpression& operator=(const DeferredExpression&) = default;
    DeferredExpression& operator=(DeferredExpression&&) noexcept = default;

    Result operator()() const { return _expr(); }

private:
    std::function<Result()> _expr;
};

namespace detail::adl {
template<typename Result>
inline std::string to_string(const DeferredExpression<Result>& x, adl::tag /*unused*/) {
    return hilti::rt::to_string(x());
}
} // namespace detail::adl

// This function is declared as an overload since we cannot partially specialize
// `hilti::detail::to_string_for_print` for `DeferredExpression<T>`.
template<typename Result>
inline std::string to_string_for_print(const DeferredExpression<Result>& x) {
    return hilti::rt::to_string_for_print(x());
}

template<typename Result>
inline std::ostream& operator<<(std::ostream& out, const DeferredExpression<Result>& x) {
    return out << to_string_for_print(x);
}

} // namespace hilti::rt
