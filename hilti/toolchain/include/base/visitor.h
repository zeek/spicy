// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <type_traits>
#include <vector>

#include <hilti/base/logger.h>
#include <hilti/base/visitor-types.h>

namespace hilti {
namespace detail::visitor {

enum class Order { Pre, Post };

// hasCallback<C,FuncSig>
// Test if Visitor class C has specific operator() 'callback' type
// (uses detection idiom SFINAE; in C++20 just use a requires clause)
//
template<class C, typename FuncSig, typename = void>
struct hasCallback : std::false_type {};

template<class C, typename FuncSig> // remove_cv used as type_identity
struct hasCallback<C, FuncSig, std::void_t<decltype(std::remove_cv_t<FuncSig C::*>{&C::operator()})>> : std::true_type {
};

template<class C, typename... FuncSig>
inline constexpr bool has_callback = (hasCallback<C, FuncSig>::value || ...);

template<typename Result>
using DispatchResult = std::conditional_t<std::is_void_v<Result>, bool, std::optional<Result>>;

template<typename Result, typename Erased, typename Dispatcher, typename Iterator>
DispatchResult<Result> do_dispatch(Erased& n, Dispatcher& d, typename Iterator::Position& i, // NOLINT
                                   bool& no_match_so_far);                                   // NOLINT

template<typename Result, typename Type, typename Erased, typename Dispatcher, typename Iterator>
DispatchResult<Result> do_dispatch_one(Erased& n, const std::type_info& ti, Dispatcher& d,
                                       typename Iterator::Position& i, bool& no_match_so_far) { // NOLINT
    if ( ti != typeid(Type) )
        return {};

    using T = std::conditional_t<std::is_const_v<Erased>, const Type, Type>;

    using CBc = Result(T const&);
    using CBcIP = Result(T const&, typename Iterator::Position);

    auto& x = n.template as<Type>();
    DispatchResult<Result> result = {};

    // Prefer most specific callback, so climb down first.
    if constexpr ( std::is_base_of_v<util::type_erasure::trait::TypeErased, Type> )
        result = do_dispatch<Result, T, Dispatcher, Iterator>(x, d, i, no_match_so_far);

    if constexpr ( std::is_void_v<Result> ) {
        // No result expected, call all matching methods.
        (void)result;
        if constexpr ( has_callback<Dispatcher, CBc> ) {
            no_match_so_far = false;
            d(x);
        }

        if constexpr ( has_callback<Dispatcher, CBcIP> ) {
            no_match_so_far = false;
            d(x, i);
        }

        return false; // Continue matching.
    }

    else { // NOLINT
        // Single result expected, stop at first matching method.
        if ( result )
            return result;

        if constexpr ( has_callback<Dispatcher, CBc> ) {
            no_match_so_far = false;
            return {d(x)};
        }

        if constexpr ( has_callback<Dispatcher, CBcIP> ) {
            no_match_so_far = false;
            return {d(x, i)};
        }
    }

    return {};
}

template<typename Result, typename Erased, typename Dispatcher, typename Iterator>
DispatchResult<Result> do_dispatch(Erased& n, Dispatcher& d, typename Iterator::Position& i, // NOLINT
                                   bool& no_match_so_far) {                                  // NOLINT
    auto& tn = n.typeid_();

#ifdef VISITOR_DISPATCHERS
    VISITOR_DISPATCHERS
#else
#error "VISITOR_DISPATCHERS not defined, did you include 'autogen/dispatchers.h'?"
#endif

    if constexpr ( std::is_void_v<Result> )
        return ! no_match_so_far;
    else // NOLINT
        return std::nullopt;
}

///////////////

template<typename Erased, Order order, bool isConst>
class Iterator {
public:
    using E = std::conditional_t<isConst, const Erased&, Erased&>;
    using Location = ::hilti::visitor::Location<E>;
    using Position = ::hilti::visitor::Position<E>;

    Iterator() = default;
    Iterator(E root) { _path.emplace_back(root, -1); }

    Iterator(const Iterator& other) = default;
    Iterator(Iterator&& other) noexcept = default;

    ~Iterator() = default;

    Iterator& operator++() {
        next();
        return *this;
    }
    Position operator*() const { return current(); }

    Iterator& operator=(const Iterator& other) = default;
    Iterator& operator=(Iterator&& other) noexcept = default;
    bool operator==(const Iterator& other) const { return _path.empty() && other._path.empty(); }

    bool operator!=(const Iterator& other) const { return ! (*this == other); }

private:
    void next() {
        if ( _path.empty() )
            return;

        auto& p = _path.back();
        p.child += 1;

        if ( p.child == -1 ) {
            if ( order == Order::Pre || p.node.pruneWalk() )
                return;

            next();
            return;
        }

        if ( p.node.pruneWalk() ) {
            _path.pop_back();
            next();
            return;
        }

        assert(p.child >= 0);

        if ( p.child < static_cast<int>(p.node.children().size()) ) {
            _path.emplace_back(p.node.children()[p.child], -2);
            next();
            return;
        }

        if ( p.child == static_cast<int>(p.node.children().size()) ) {
            if constexpr ( order == Order::Post )
                return;

            p.child += 1;
        }

        if ( p.child > static_cast<int>(p.node.children().size()) ) {
            _path.pop_back();
            next();
            return;
        }
    }

    Position current() const {
        if ( _path.empty() )
            throw std::runtime_error("invalid reference of visitor's iterator");

        auto& p = _path.back();

        if ( p.child < 0 ) // pre order
            return Position{.node = p.node, .path = _path};

        if ( p.child == static_cast<int>(p.node.children().size()) ) // post order
            return Position{.node = p.node, .path = _path};

        assert(p.child < static_cast<int>(p.node.children().size()));
        return Position{.node = p.node.children()[p.child], .path = _path};
    }

    std::vector<Location> _path;
};

template<typename Visitor>
class ConstView {
public:
    using iterator_t = typename Visitor::const_iterator_t;

    ConstView(const typename Visitor::erased_t& root) : _root(root) {}

    auto begin() {
        if constexpr ( Visitor::order_ == Order::Pre )
            return iterator_t(_root);

        return ++iterator_t(_root);
    }

    auto end() { return iterator_t(); }

private:
    const typename Visitor::erased_t& _root;
};

template<typename Visitor>
class NonConstView {
public:
    using iterator_t = typename Visitor::iterator_t;

    NonConstView(typename Visitor::erased_t& root) : _root(root) {}

    auto begin() {
        if constexpr ( Visitor::order_ == Order::Pre )
            return iterator_t(_root);

        return ++iterator_t(_root);
    }

    auto end() { return iterator_t(); }

private:
    typename Visitor::erased_t& _root;
};

/**
 * AST visitor.
 *
 * @tparam Result type the dispatch methods (and hence the visitor) returns
 * @tparam Dispatcher class defining dispatch methods
 * @tparam Erased type-erased class to dispatch on
 * @tparam order order of iteration
 */
template<typename Result, typename Dispatcher, typename Erased, Order order>
class Visitor {
public:
    using result_t = Result;
    using erased_t = Erased;
    using base_t = Visitor<Result, Dispatcher, Erased, order>;
    using visitor_t = Dispatcher;
    using iterator_t = Iterator<Erased, order, false>;
    using const_iterator_t = Iterator<Erased, order, true>;
    using position_t = typename iterator_t::Position;
    using const_position_t = typename const_iterator_t::Position;
    static const Order order_ = order;

    Visitor() = default;
    virtual ~Visitor() = default;

    virtual void preDispatch(const Erased& /* n */, int /* level */){};

    /** Execute matching dispatch methods for a single node.  */
    auto dispatch(position_t& i) {
        bool no_match_so_far = true;
        preDispatch(i.node, i.pathLength());
        return do_dispatch<Result, Erased, Dispatcher, iterator_t>(i.node, *static_cast<Dispatcher*>(this), i,
                                                                   no_match_so_far);
    }

    /** Execute matching dispatch methods for a single node.  */
    auto dispatch(const_position_t& i) {
        bool no_match_so_far = true;
        preDispatch(i.node, i.pathLength());
        return do_dispatch<Result, const Erased, Dispatcher, const_iterator_t>(i.node, *static_cast<Dispatcher*>(this),
                                                                               i, no_match_so_far);
    }

    /**
     * Execute matching dispatch methods for a single node.
     *
     * This method takes just the node itself and operates as it were the
     * root of an AST.
     */
    auto dispatch(Erased* n) {
        bool no_match_so_far = true;
        std::vector<typename iterator_t::Location> path;
        position_t i = {*n, path};
        preDispatch(*n, 0);
        return do_dispatch<Result, Erased, Dispatcher, iterator_t>(*n, *static_cast<Dispatcher*>(this), i,
                                                                   no_match_so_far);
    }

    /**
     * Execute matching dispatch methods for a single node.
     *
     * This method takes just the node itself and operates as it were the
     * root of an AST.
     */
    auto dispatch(const Erased& n) {
        Erased n_ = n;
        bool no_match_so_far = true;
        std::vector<typename iterator_t::Location> path;
        position_t i = {n_, path};
        preDispatch(n_, 0);
        return do_dispatch<Result, Erased, Dispatcher, iterator_t>(n_, *static_cast<Dispatcher*>(this), i,
                                                                   no_match_so_far);
    }

    /**
     * Iterate over AST and Execute matching dispatch methods for each node.
     *
     * This method operates on a constant AST, and the dispatcher cannot
     * modify any nodes.
     *
     * @note The returned view operates on references to the the AST passed
     * in, so make sure that stays around as long as necessary.
     */
    auto walk(const Erased& root) { return ConstView<Visitor>(root); }

    /**
     * Iterate over AST and Execute matching dispatch methods for each node.
     *
     * This method operates on a non-constant AST, and the dispatcher may
     * modify nodes.
     *
     * @note The returned view operates on references to the the AST passed
     * in, so make sure that stays around as long as necessary.
     */
    auto walk(Erased* root) { return NonConstView<Visitor>(*root); }
};

using NoDispatcher = struct {};

} // namespace detail::visitor

/**
 * Visitor performing a pre-order iteration over an AST.
 */
namespace visitor {
template<typename Result = void, typename Dispatcher = detail::visitor::NoDispatcher, typename Erased = Node>
using PreOrder = detail::visitor::Visitor<Result, Dispatcher, Erased, detail::visitor::Order::Pre>;

/**
 * Visitor performing a post-order iteration over an AST.
 */
template<typename Result = void, typename Dispatcher = detail::visitor::NoDispatcher, typename Erased = Node>
using PostOrder = detail::visitor::Visitor<Result, Dispatcher, Erased, detail::visitor::Order::Post>;

} // namespace visitor

} // namespace hilti
