// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <cinttypes>
#include <functional>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace hilti::trait {
class isNode {};
} // namespace hilti::trait

#include <hilti/ast/doc-string.h>
#include <hilti/ast/meta.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/scope.h>
#include <hilti/base/type_erase.h>
#include <hilti/base/util.h>

namespace hilti {

class Node;

namespace node {

template<typename T>
class Range;

template<typename T>
class Set;

namespace detail {

/** Value of a node property, stored as part of `Properties`. */
using PropertyValue = std::variant<bool, const char*, double, int, int64_t, unsigned int, uint64_t, std::string>;

/** Renders a property value into a string for display. */
inline std::string to_string(const PropertyValue& v) {
    struct Visitor {
        auto operator()(bool s) { return std::string(s ? "true" : "false"); }
        auto operator()(const char* s) { return util::escapeUTF8(s); }
        auto operator()(double d) { return util::fmt("%.6f", d); }
        auto operator()(int i) { return util::fmt("%d", i); }
        auto operator()(int64_t i) { return util::fmt("%" PRId64, i); }
        auto operator()(const std::string& s) { return util::escapeUTF8(s); }
        auto operator()(unsigned int u) { return util::fmt("%u", u); }
        auto operator()(uint64_t u) { return util::fmt("%" PRIu64, u); }
    };

    return std::visit(Visitor(), v);
};

} // namespace detail

/** Importance of reporting an error, relative to others. */
enum class ErrorPriority {
    High = 3,   /**< high priority error that will always be reported */
    Normal = 2, /**< normal priority error that will be reported if there are no higher priority ones */
    Low = 1,    /**< low priority error that will be reported if there are no higher priority ones */
    NoError = 0 /**< place-holder for comparison if no error was encountered */
};

inline bool operator<(ErrorPriority x, ErrorPriority y) {
    return static_cast<std::underlying_type_t<ErrorPriority>>(x) <
           static_cast<std::underlying_type_t<ErrorPriority>>(y);
}

/** Error information associated with nodes. */
struct Error {
    std::string message;                            /**< main error message to report  */
    Location location;                              /**< location associated with the error */
    std::vector<std::string> context;               /**< additional lines to print along with error as context */
    ErrorPriority priority = ErrorPriority::Normal; /**< priortity of error */

    // Comparison considers message & location, so that we can unique based
    // on those two.
    bool operator<(const Error& other) const {
        return std::tie(message, location) < std::tie(other.message, other.location);
    }
};

/**
 * Properties associated with an AST node. A property is a key/value pair
 * recording node-specific, atomic information that's not represented by
 * further child nodes.
 */
using Properties = std::map<std::string, node::detail::PropertyValue>;

namespace detail {
#include <hilti/autogen/__node.h>

} // namespace detail
} // namespace node

/**
 * AST node. This is a type-erased class that wraps all AST nodes.
 *
 * @note Do not derive from this class. Derive from `NodeBase` instead and
 * then implement the `Node` interface.
 */
class Node final : public node::detail::Node {
public:
    /** Constructs a node from an instance of a class implementing the `Node` interface. */
    template<typename T, typename std::enable_if_t<std::is_base_of<trait::isNode, T>::value>* = nullptr>
    Node(T t) : node::detail::Node(std::move(t)) {}

    Node(const Node& other) : node::detail::Node::Node(other), _scope(other._scope) {}

    Node(Node&& other) noexcept
        : node::detail::Node::Node(std::move(other)),
          _control_ptr(std::move(other._control_ptr)),
          _scope(std::move(other._scope)),
          _errors(std::move(other._errors)) {
        if ( _control_ptr )
            _control_ptr->_node = this;
    }

    Node() = delete;

    ~Node() final {
        if ( _control_ptr )
            _control_ptr->_node = nullptr;
    }

    /**
     * Returns the node's unique control ID if there's at least `NodeRef` has
     * been created that refers to it. If there's no such NodeRef, returns
     * zero.
     *
     * @note This is primarily for internal usage.
     */
    uint64_t rid() const { return _control_ptr ? _control_ptr->_rid : 0; }

    /**
     * Returns a string representation of `rid()`.
     *
     * @note This is primarily for internal usage.
     */
    std::string renderedRid() const { return rid() ? util::fmt("%%%" PRIu64, rid()) : "%???"; };

    /**
     * Returns the scope associated with the node. All nodes have a scope
     * used for ID resolution. Initially, a new node receive its own, empty
     * scope. However, scopes can be shared across nodes through
     * `setScope()`.
     */
    IntrusivePtr<Scope> scope() const {
        if ( ! _scope )
            _scope = make_intrusive<Scope>();

        return _scope;
    }

    /**
     * Resets the node's scope to point to another one.
     */
    void setScope(IntrusivePtr<Scope> new_scope) { _scope = std::move(new_scope); }

    /** Clears out the current scope. */
    void clearScope() {
        if ( ! _scope )
            return;

        // Don't just clear the items because the scope might be shared with
        // other nodes.
        _scope = make_intrusive<Scope>();
    }

    /** Returns any error messages associated with the node. */
    std::vector<node::Error> errors() const {
        if ( _errors )
            return *_errors;
        else
            return {};
    }

    /** Returns true if there are any errors associated with the node. */
    bool hasErrors() const { return _errors && _errors->size(); }

    /** Clears any error message associated with the node. */
    void clearErrors() {
        if ( _errors )
            _errors.reset();
    }

    /**
     * Associate an error message with the node. The error's location will be
     * that of the current node, and it will have normal priority.
     *
     * @param msg error message to report
     * @param context further lines of context to show along with error
     *
     */
    void addError(std::string msg, std::vector<std::string> context = {}) {
        addError(std::move(msg), location(), std::move(context));
    }

    /**
     * Associate an error message with the node. The error's location will be
     * that of the current node.
     *
     * @param msg error message to report
     * @param priority importance of showing the error
     * @param context further lines of context to show along with error
     *
     */
    void addError(std::string msg, node::ErrorPriority priority, std::vector<std::string> context = {}) {
        addError(std::move(msg), location(), priority, std::move(context));
    }

    /**
     * Associate an error message with the node. The error will have normal
     * priority.
     *
     * @param msg error message to report
     * @param l custom location to associate with the error
     * @param context further lines of context to show along with error
     */
    void addError(std::string msg, const Location& l, std::vector<std::string> context = {}) {
        addError(std::move(msg), location(), node::ErrorPriority::Normal, std::move(context));
    }

    /**
     * Associate an error message with the node.
     *
     * @param msg error message to report
     * @param l custom location to associate with the error
     * @param priority importance of showing the error
     * @param context further lines of context to show along with error
     */
    void addError(std::string msg, Location l, node::ErrorPriority priority, std::vector<std::string> context = {}) {
        node::Error error;
        error.message = std::move(msg);
        error.location = std::move(l);
        error.context = std::move(context);
        error.priority = priority;

        if ( ! _errors )
            _errors = std::make_unique<std::vector<node::Error>>();

        _errors->push_back(std::move(error));
    }

    /**
     * Recursively clears all child nodes and then deletes them from this node.
     * This helps to break reference cycles.
     */
    void destroyChildren();

    /**
     * Returns an internal string representation of the node and all its
     * children.
     *
     * @param include_location if true, include source code locations into
     * the output
     */
    std::string render(bool include_location = true) const;

    /**
     * Print out a HILTI source code representation of the node and all its
     * children. If the node is not the root of an AST, it's not guaranteed
     * that the result will form valid HILTI source code (but it can still be
     * used, e.g., in error messages).
     *
     * @param out output stream
     * @param compact create a one-line representation
     *
     */
    void print(std::ostream& out, bool compact = false) const;

    /**
     * Returns a HILTI source code representation of the node and all its
     * children. This can be called from inside a debugger.
     */
    std::string print() const;

    /** Convenience method to return the meta data's location information. */
    const Location& location() const { return meta().location(); }

    /** Aborts execution if node is not of a given type `T`. */
    template<typename T>
    void assertIsA() {
        if ( ! isA<T>() ) {
            std::cerr << "Assertion failure: Node expected to be a " << typeid(T).name() << " but is a "
                      << typeid_().name() << std::endl;
            util::abort_with_backtrace();
        }
    }

    /** Renders the node as HILTI source code. */
    operator std::string() const { return print(); }

    /**
     * Replaces the node with another one. Existing `NodeRef` pointing to
     * this node will remain valid and reflect the new value.
     */
    Node& operator=(const Node& n) {
        if ( &n == this )
            return *this;

        _scope = n._scope;
        node::detail::ErasedBase::operator=(n);
        return *this;
    }

    /**
     * Replaces the node with another one. Existing `NodeRef` pointing to
     * this node will remain valid and reflect the new value.
     */
    Node& operator=(Node&& n) noexcept {
        _scope = std::move(n._scope);
        node::detail::ErasedBase::operator=(std::move(n));
        return *this;
    }

    /**
     * Replaces the node with an instance of a class implementing the `Node`
     * interface. Existing `NodeRef` pointing to this node will remain valid
     * and reflect the new value.
     */
    template<typename T>
    Node& operator=(const T& t) {
        node::detail::ErasedBase::operator=(to_node(t));
        return *this;
    }

private:
    friend class NodeRef;

    // Returns (and potentially creates) the control block for this node that
    // `NodeRef` uses to maintain links to it.
    IntrusivePtr<node_ref::detail::Control> _control() const {
        if ( ! _control_ptr )
            _control_ptr = make_intrusive<node_ref::detail::Control>(this);

        return _control_ptr;
    }

    mutable IntrusivePtr<node_ref::detail::Control> _control_ptr = nullptr;
    mutable IntrusivePtr<Scope> _scope = nullptr;
    std::unique_ptr<std::vector<node::Error>> _errors = nullptr;
};

/**
 * Common base class for classes implementing the `Node` interface. The base
 * implements a number of the interface methods with standard versions shared
 * across all nodes.
 */
class NodeBase : public trait::isNode {
public:
    /**
     * Constructor.
     *
     * @param meta meta information to associate with the node
     */
    NodeBase(Meta meta) : _meta(std::move(meta)) {}

    /**
     * Constructor registering child nodes.
     *
     * @param children children of this node
     * @param meta meta information to associate with the node
     */
    NodeBase(std::vector<Node> children, Meta meta) : _meta(std::move(meta)) {
        for ( auto& c : children )
            addChild(std::move(c));
    }

    NodeBase() = default;

    /**
     * Returns a child.
     *
     * @tparam T type that the child nodes are assumed to (and must) have
     * @param i index of the child, in the order they were passed into the constructor and/or added
     * @return child casted to type `T`
     */
    template<typename T>
    const T& child(int i) const {
        return _children[i].as<T>();
    }

    /**
     * Aborts execution if a given child is not an expected type `T`.
     *
     * @tparam T type that the child node is assumed to have
     * @param i index of the child, in the order they were passed into the constructor and/or added
     */
    template<typename T>
    void assertChildIsA(int i) {
        _children[i].template assertIsA<T>();
    }

    /**
     * Returns a subrange of children. The indices correspond to the order
     * children were passed into the constructor and/or added.
     *
     * @tparam T type that the child nodes are assumed to (and must) have
     * @param begin index of first child to include; a negative index counts Python-style from end of list
     * @param end index of one beyond last child to include; a negative index counts Python-style from end of list
     * @return range containing children from `start` to `end`
     */
    template<typename T>
    auto children(int begin, int end) const {
        auto end_ = (end < 0) ? _children.end() : _children.begin() + end;
        return hilti::node::Range<T>(_children.begin() + begin, end_);
    }

    /**
     * Returns a references to a subrange of children. The indices correspond
     * to the order children were passed into the constructor and/or added.
     *
     * @param begin index of first child to include; a negative index counts Python-style from end of list
     * @param end index of one beyond last child to include; a negative index counts Python-style from end of list
     * @return vector containing child references from `start` to `end`
     */
    auto childRefs(int begin, int end) {
        auto end_ = (end < 0) ? _children.end() : _children.begin() + end;

        std::vector<NodeRef> refs;
        for ( auto c = _children.begin(); c != end_; c = std::next(c) )
            refs.emplace_back(*c);

        return refs;
    }

    /**
     * Returns a subset of children selected by their type.
     *
     * @tparam T type of children to return
     * @return set of all children that have type `T`
     */
    template<typename T>
    hilti::node::Set<T> childrenOfType() const;

    /**
     * Returns a vector of references to a subset of children selected by their
     * type.
     *
     * @tparam T type of children to return
     * @return set of all children that have type `T`
     */
    template<typename T>
    std::vector<NodeRef> childRefsOfType() const;

    /**
     * Adds a child node. It will be appended to the end of the current list
     * node of children.
     */
    void addChild(Node n) {
        if ( _meta.location() && ! n.location() ) {
            auto m = n.meta();
            m.setLocation(_meta.location());
            n.setMeta(std::move(m));
        }

        _children.push_back(std::move(n));
    }

    /** Implements the `Node` interface. */
    const auto& children() const { return _children; }
    /** Implements the `Node` interface. */
    auto& children() { return _children; }
    /** Implements the `Node` interface. */
    auto& meta() const { return _meta; }
    /** Implements the `Node` interface. */
    void setMeta(Meta m) { _meta = std::move(m); }
    /** Implements the `Node` interface. */
    bool pruneWalk() const { return false; }

private:
    std::vector<::hilti::Node> _children;
    Meta _meta;
    NodeRef _orig;
};

namespace node {

/** Common mix-in class for nodes storing doc strings. */
class WithDocString {
public:
    /** Returns the documentation associated with the declaration, if any. */
    const std::optional<DocString>& documentation() const { return _doc; }

    /** Clears out any documentation associated with the declaration. */
    void clearDocumentation() { _doc.reset(); }

    /** Sets the documentation associated with the declaration. */
    void setDocumentation(DocString doc) {
        if ( doc )
            _doc = std::move(doc);
        else
            _doc.reset();
    }

private:
    std::optional<DocString> _doc;
};

/** Place-holder node for an optional node that's not set. */
class None : public NodeBase, public util::type_erasure::trait::Singleton {
public:
    /** Implements the `Node` interface. */
    auto properties() const { return node::Properties{}; }

    /**
     * Wrapper around constructor so that we can make it private. Don't use
     * this, use the singleton `type::unknown` instead.
     */
    static None create() { return None(); }

private:
    None() : NodeBase(Meta()) {}
};

/** Singleton. */
extern const Node none;

/**
 * A constant iterator over a range of nodes (`node::Range`). Internally, this
 * wrap around a vector iterator, and is adapted from
 * https://www.artificialworlds.net/blog/2017/05/12/c-iterator-wrapperadaptor-example.
 */
template<typename T>
class RangeIterator {
    using BaseIterator = std::vector<Node>::const_iterator;

public:
    using value_type = BaseIterator::value_type;
    using difference_type = BaseIterator::difference_type;
    using pointer = BaseIterator::pointer;
    using reference = BaseIterator::reference;
    using iterator_category = BaseIterator::iterator_category;

    explicit RangeIterator(BaseIterator i) : _iter(i) {}
    RangeIterator(const RangeIterator& other) = default;
    RangeIterator(RangeIterator&& other) noexcept = default;
    RangeIterator() {}
    ~RangeIterator() = default;

    const Node& node() const { return *_iter; }

    RangeIterator& operator=(const RangeIterator& other) = default;
    RangeIterator& operator=(RangeIterator&& other) noexcept = default;
    const T& operator*() const { return value(); }
    const T* operator->() const { return &value(); }
    bool operator==(const RangeIterator& other) const { return _iter == other._iter; }
    bool operator!=(const RangeIterator& other) const { return ! (*this == other); }

    RangeIterator operator++(int) {
        auto x = RangeIterator(_iter);
        ++_iter;
        return x;
    }

    RangeIterator& operator++() {
        ++_iter;
        return *this;
    }

    RangeIterator& operator+=(difference_type i) {
        _iter += i;
        return *this;
    }

    RangeIterator& operator-=(difference_type i) {
        _iter -= i;
        return *this;
    }

    difference_type operator-(const RangeIterator& other) const { return _iter - other._iter; }
    RangeIterator operator-(difference_type i) const { return RangeIterator(_iter - i); }
    RangeIterator operator+(difference_type i) const { return RangeIterator(_iter + i); }

private:
    const T& value() const { return (*_iter).template as<std::remove_const_t<T>>(); }

    BaseIterator _iter;
};

/**
 * A range of AST nodes, defined by start and end into an existing vector of
 * nodes. The range creates a view that can be iterated over, yielding a
 * reference to each node in turn.
 */
template<typename T>
class Range {
public:
    using iterator = RangeIterator<T>;
    using const_iterator = RangeIterator<T>;

    explicit Range() {}
    Range(std::vector<Node>::const_iterator begin, std::vector<Node>::const_iterator end) : _begin(begin), _end(end) {}

    explicit Range(const std::vector<Node>& nodes) : Range(nodes.begin(), nodes.end()) {}

    Range(const Range& other) = default;
    Range(Range&& other) noexcept = default;
    ~Range() = default;

    auto begin() const { return const_iterator(_begin); }
    auto end() const { return const_iterator(_end); }
    size_t size() const { return static_cast<size_t>(_end - _begin); }
    const T& front() const { return *_begin; }
    bool empty() const { return _begin == _end; }

    /**
     * Returns a new vector containing copies of all nodes that the range
     * includes.
     **/
    std::vector<T> copy() const {
        std::vector<T> x;
        for ( auto i = _begin; i != _end; i++ )
            x.push_back(*i);

        return x;
    }

    const T& operator[](size_t i) const {
        assert(static_cast<typename RangeIterator<T>::difference_type>(i) < std::distance(_begin, _end));
        return *(_begin + i);
    }

    bool operator==(const Range& other) const {
        if ( this == &other )
            return true;

        if ( size() != other.size() )
            return false;

        auto x = _begin;
        auto y = other._begin;
        while ( x != _end ) {
            if ( ! (*x++ == *y++) )
                return false;
        }

        return true;
    }

    Range& operator=(const Range& other) = default;
    Range& operator=(Range&& other) noexcept = default;

private:
    RangeIterator<T> _begin;
    RangeIterator<T> _end;
};

/**
 * A constant iterator over a set of nodes (`node::Set`). The content of the
 * set is sorted by the order that nodes were added. Internally, this wraps
 * around a iterator over a vector of node references, and is adapted from
 * https://www.artificialworlds.net/blog/2017/05/12/c-iterator-wrapperadaptor-example.
 */
template<typename T>
class SetIterator {
    using BaseIterator = typename std::vector<std::reference_wrapper<const T>>::const_iterator;

public:
    // Previously provided by std::iterator
    using value_type = T;
    using difference_type = typename BaseIterator::difference_type;
    using pointer = typename BaseIterator::pointer;
    using reference = typename BaseIterator::reference;
    using iterator_category = typename BaseIterator::iterator_category;

    explicit SetIterator(BaseIterator i) : _iter(std::move(i)) {}
    SetIterator(const SetIterator& other) = default;
    SetIterator(SetIterator&& other) noexcept = default;
    SetIterator() {}
    ~SetIterator() = default;

    const Node& node() const { return *_iter; }

    SetIterator& operator=(const SetIterator& other) = default;
    SetIterator& operator=(SetIterator&& other) noexcept = default;
    const T& operator*() const { return value(); }
    const T* operator->() const { return &value(); }
    bool operator==(const SetIterator& other) const { return _iter == other._iter; }
    bool operator!=(const SetIterator& other) const { return ! (*this == other); }

    SetIterator operator++(int) {
        auto x = SetIterator(_iter);
        ++_iter;
        return x;
    }

    SetIterator& operator++() {
        ++_iter;
        return *this;
    }

    SetIterator& operator+=(difference_type i) {
        _iter += i;
        return *this;
    }

    SetIterator& operator-=(difference_type i) {
        _iter -= i;
        return *this;
    }

    difference_type operator-(const SetIterator& other) const { return _iter - other._iter; }
    SetIterator operator-(difference_type i) const { return SetIterator(_iter - i); }
    SetIterator operator+(difference_type i) const { return SetIterator(_iter + i); }

private:
    const T& value() const { return ((*_iter).get()); }

    BaseIterator _iter;
};

/**
 * A set of AST nodes. The set creates a view of nodes that can be iterated
 * over, yielding a reference to each node in turn. In contrast to `Range`, a
 * set can include nodes that are not all part of a continuous slice inside a
 * vector.
 */
template<typename T>
class Set {
public:
    using iterator = SetIterator<T>;
    using const_iterator = SetIterator<T>;

    Set() {}
    Set(const Set& other) = default;
    Set(Set&& other) noexcept = default;
    ~Set() = default;

    auto begin() const { return const_iterator(_set.begin()); }
    auto end() const { return const_iterator(_set.end()); }
    size_t size() const { return _set.size(); }
    bool empty() const { return _set.empty(); }
    void insert(const T& t) { _set.push_back(t); }

    /**
     * Returns a new vector containing copies of all nodes that the range
     * includes.
     **/
    std::vector<T> copy() const {
        std::vector<T> x;
        for ( auto i = begin(); i != end(); i++ )
            x.push_back(*i);

        return x;
    }

    const T& operator[](size_t i) const { return *(begin() + i); }

    bool operator==(const Set& other) const {
        if ( this == &other )
            return true;

        if ( size() != other.size() )
            return false;

        auto x = begin();
        auto y = other.begin();
        while ( x != end() ) {
            if ( ! (*x++ == *y++) )
                return false;
        }

        return true;
    }

    Set& operator=(const Set& other) = default;
    Set& operator=(Set&& other) noexcept = default;

private:
    std::vector<std::reference_wrapper<const T>> _set;
};


} // namespace node

inline const Node& to_node(const node::None& /* n */) { return node::none; }

/**
 * No-op function implementing the `to_node` API for instances that already
 * are of type `Node`.
 */
template<typename T, IF_SAME(T, Node)> // Don't allow derived classes.
inline Node to_node(const T& n) {
    return n;
}

/** Implements the `to_node` API for optional nodes. */
template<typename T>
Node to_node(std::optional<T> t) {
    if ( t )
        return to_node(std::move(*t));

    return to_node(node::none);
}

/**
 * Creates `Node` instances for a vector of objects all implementing the
 * `Node` interface.
 */
template<typename T>
std::vector<Node> nodes(std::vector<T> t) {
    std::vector<Node> v;
    v.reserve(t.size());
    for ( const auto& i : t )
        v.emplace_back(std::move(i));

    return v;
}

/**
 * Creates `Node` instances for a list of objects all implementing the
 * `Node` interface.
 */
template<typename T>
std::vector<Node> nodes(std::list<T> t) {
    std::vector<Node> v;
    for ( const auto& i : t )
        v.emplace_back(std::move(i));

    return v;
}

/**
 * Copies a ramge of nodes over into a vector. Note that as with all copies of
 * node, this performs shallow copying.
 */
template<typename T>
std::vector<Node> nodes(hilti::node::Range<T> t) {
    std::vector<Node> v;
    v.reserve(t.size());
    for ( const auto& i : t )
        v.emplace_back(std::move(i));

    return v;
}

/** Create a 1-element vector of nodes for an object implementing the `Node` API. */
template<typename T>
std::vector<Node> nodes(T t) {
    return {to_node(std::move(t))};
}

/**
 * Creates `Node` instances for objects all implementing the `Node`
 * interface.
 */
template<typename T, typename... Ts>
std::vector<Node> nodes(T t, Ts... ts) {
    return util::concat(nodes(t), nodes(std::move(ts)...));
}

/**
 * Checks equality for two objects both implementing the `Node` interface.
 *
 * If the two objects have different types, this will return false. Otherwise
 * it will forward to the objects equality operator.
 */
namespace node {
template<typename T, typename Other, IF_DERIVED_FROM(T, trait::isNode), IF_DERIVED_FROM(Other, trait::isNode)>
bool isEqual(const T* this_, const Other& other) {
    if ( const auto o = other.template tryAs<T>() )
        return *this_ == *o;

    return false;
}

/**
 * Filters a node vector through a boolean predicate, returning a set
 * containing the matching ones.
 */
template<typename X, typename F>
auto filter(const hilti::node::Range<X>& x, F f) {
    hilti::node::Set<X> y;
    for ( const auto& i : x ) {
        if ( f(i) )
            y.push_back(i);
    }

    return y;
}

/**
 * Filters a node set through a boolean predicate, returning a new set
 * containing the matching ones.
 */
template<typename X, typename F>
auto filter(const hilti::node::Set<X>& x, F f) {
    hilti::node::Set<X> y;
    for ( const auto& i : x ) {
        if ( f(i) )
            y.insert(i);
    }

    return y;
}

/**
 * Applies a function to each element of a node range, returning a new vector
 * with the results.
 */
template<typename X, typename F>
auto transform(const hilti::node::Range<X>& x, F f) {
    using Y = typename std::invoke_result_t<F, X&>;
    std::vector<Y> y;
    y.reserve(x.size());
    for ( const auto& i : x )
        y.push_back(f(i));

    return y;
}

/**
 * Applies a function to each element of a node set, returning a new vector of
 * with the results.
 */
template<typename X, typename F>
auto transform(const hilti::node::Set<X>& x, F f) {
    using Y = typename std::invoke_result_t<F, X&>;
    std::vector<Y> y;
    y.reserve(x.size());
    for ( const auto& i : x )
        y.push_back(f(i));

    return y;
}


} // namespace node

/** Renders a node as HILTI source code. */
inline std::ostream& operator<<(std::ostream& out, const Node& n) {
    n.print(out, true);
    return out;
}

template<typename T>
hilti::node::Set<T> NodeBase::childrenOfType() const {
    typename hilti::node::Set<T> n;
    for ( auto c = _children.begin(); c != _children.end(); c = std::next(c) ) {
        if ( auto t = c->tryAs<T>() )
            n.insert(*t);
    }

    return n;
}

template<typename T>
std::vector<NodeRef> NodeBase::childRefsOfType() const {
    typename std::vector<NodeRef> n;
    for ( auto c = _children.begin(); c != _children.end(); c = std::next(c) ) {
        if ( c->isA<T>() )
            n.emplace_back(*c);
    }

    return n;
}

namespace node {
namespace detail {
// Backend to NodeBase::flattenedChildren.
void flattenedChildren(const hilti::Node& n, node::Set<hilti::Node>* dst);
} // namespace detail

/**
 * Returns a list of all children of specific type, descending recursively
 * to find instance anywhere below this node.
 */
inline node::Set<Node> flattenedChildren(const Node& n) {
    node::Set<Node> dst;
    detail::flattenedChildren(n, &dst);
    return dst;
}

} // namespace node

} // namespace hilti
