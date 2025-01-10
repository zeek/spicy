// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

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
template<typename Result, typename Expr>
class DeferredExpression {
public:
    DeferredExpression(Expr&& expr) : _expr(std::move(expr)) {}
    DeferredExpression() = delete;
    DeferredExpression(const DeferredExpression&) = default;
    DeferredExpression(DeferredExpression&&) noexcept = default;

    ~DeferredExpression() = default;

    DeferredExpression& operator=(const DeferredExpression&) = default;
    DeferredExpression& operator=(DeferredExpression&&) noexcept = default;

    Result operator()() const { return _expr(); }

private:
    Expr _expr;
};

template<typename Result, typename Expr>
auto make_deferred(Expr&& expr) {
    return DeferredExpression<Result, Expr>(std::forward<Expr>(expr));
}

namespace detail::adl {
template<typename Result, typename Expr>
inline std::string to_string(const DeferredExpression<Result, Expr>& x, adl::tag /*unused*/) {
    return hilti::rt::to_string(x());
}
} // namespace detail::adl

// This function is declared as an overload since we cannot partially specialize
// `hilti::detail::to_string_for_print` for `DeferredExpression<T, Expr>`.
template<typename Result, typename Expr>
inline std::string to_string_for_print(const DeferredExpression<Result, Expr>& x) {
    return hilti::rt::to_string_for_print(x());
}

template<typename Result, typename Expr>
inline std::ostream& operator<<(std::ostream& out, const DeferredExpression<Result, Expr>& x) {
    return out << to_string_for_print(x);
}

} // namespace hilti::rt
