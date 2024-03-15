// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <cinttypes>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/doc-string.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/id.h>
#include <hilti/ast/meta.h>
#include <hilti/ast/node-range.h>
#include <hilti/ast/node-tag.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/visitor-dispatcher.h>

#define __HILTI_NODE_COMMON_final(NS, CLASS)                                                                           \
    ::hilti::Node* _clone(::hilti::ASTContext* ctx) const final { return ctx->make<CLASS>(*this); }

#define __HILTI_NODE_COMMON_override(NS, CLASS)

#define __HILTI_NODE_COMMON(NS, CLASS, override_)                                                                      \
    friend class ::NS::builder::NodeBuilder;                                                                           \
    friend class hilti::ASTContext;                                                                                    \
    friend class hilti::Node;                                                                                          \
    std::string _typename() const override { return hilti::util::typename_(*this); }                                   \
    __HILTI_NODE_COMMON_##override_(NS, CLASS)

#define __HILTI_NODE_0(NS, CLASS, override_)                                                                           \
    __HILTI_NODE_COMMON(NS, CLASS, override_)                                                                          \
                                                                                                                       \
    static constexpr uint16_t NodeLevel = 1;                                                                           \
    static constexpr ::hilti::node::Tag NodeTag = ::hilti::node::tag::CLASS;                                           \
    static constexpr ::hilti::node::Tags NodeTags = {::hilti::node::tag::Node, ::hilti::node::tag::CLASS};

#define HILTI_NODE_0(CLASS, override_)                                                                                 \
    __HILTI_NODE_0(hilti, CLASS, override_)                                                                            \
                                                                                                                       \
    void dispatch(::hilti::visitor::Dispatcher& v) override_ {                                                         \
        v(static_cast<::hilti::Node*>(this));                                                                          \
        v(this);                                                                                                       \
    }

#define __HILTI_NODE_1(NS, CLASS, BASE, override_)                                                                     \
    __HILTI_NODE_COMMON(NS, CLASS, override_)                                                                          \
                                                                                                                       \
    static constexpr uint16_t NodeLevel = 2;                                                                           \
    static constexpr ::hilti::node::Tag NodeTag = ::hilti::node::tag::CLASS;                                           \
    static constexpr ::hilti::node::Tags NodeTags = {::hilti::node::tag::Node, ::hilti::node::tag::BASE,               \
                                                     ::hilti::node::tag::CLASS};

#define HILTI_NODE_1(CLASS, BASE, override_)                                                                           \
    __HILTI_NODE_1(hilti, CLASS, BASE, override_)                                                                      \
                                                                                                                       \
    void dispatch(::hilti::visitor::Dispatcher& v) override_ {                                                         \
        v(static_cast<::hilti::Node*>(this));                                                                          \
        v(static_cast<BASE*>(this));                                                                                   \
        v(this);                                                                                                       \
    }

#define __HILTI_NODE_2(NS, CLASS, BASE1, BASE2, override_)                                                             \
    __HILTI_NODE_COMMON(NS, CLASS, override_)                                                                          \
                                                                                                                       \
    static constexpr uint16_t NodeLevel = 3;                                                                           \
    static constexpr ::hilti::node::Tag NodeTag = ::hilti::node::tag::CLASS;                                           \
    static constexpr ::hilti::node::Tags NodeTags = {::hilti::node::tag::Node, ::hilti::node::tag::BASE2,              \
                                                     ::hilti::node::tag::BASE1, ::hilti::node::tag::CLASS};

#define HILTI_NODE_2(CLASS, BASE1, BASE2, override_)                                                                   \
    __HILTI_NODE_2(hilti, CLASS, BASE1, BASE2, override_)                                                              \
                                                                                                                       \
    void dispatch(::hilti::visitor::Dispatcher& v) override_ {                                                         \
        v(static_cast<::hilti::Node*>(this));                                                                          \
        v(static_cast<BASE1*>(this));                                                                                  \
        v(static_cast<BASE2*>(this));                                                                                  \
        v(this);                                                                                                       \
    }

namespace hilti {
namespace builder {
class NodeBuilder;
}

/**
 * Container storing a set of nodes. This is just a `std::vector` with an
 * additional constructor.
 */
class Nodes : public std::vector<Node*> {
public:
    using std::vector<Node*>::vector;

    /** Constructor accepting a vector of pointers to a derived class. */
    template<typename T>
    Nodes(std::vector<T*> m) {
        for ( auto&& x : m )
            emplace_back(std::move(x));
    }
};

namespace node {

namespace detail {
/** Backend for `node::deepcopy()`, see there. */
Node* deepcopy(ASTContext* ctx, Node* n, bool force);
} // namespace detail

/**
 * Deep-copies a node by creating new instances of a node itself and,
 * recursively, any of its children.
 *
 * If `force` is true, this always happens. If `force` it false, the copy takes
 * place only if the node does not currently have a parent node, meaning it's
 * not part of an AST. The latter behavior is usually what one wants because
 * it performs the copy only if then adding the node to an AST.
 */
template<typename T>
T* deepcopy(ASTContext* ctx, T* n, bool force = false) {
    if ( ! n )
        return nullptr;

    return detail::deepcopy(ctx, n, force)->template as<T>();
}

/** Value of a node property, stored as part of `Properties`. */
using PropertyValue = std::variant<bool, const char*, double, int, int64_t, unsigned int, uint64_t, std::string, ID,
                                   std::optional<uint64_t>>;

/** Renders a property value into a string for display. */
inline std::string to_string(const PropertyValue& v) {
    struct Visitor {
        auto operator()(bool s) { return std::string(s ? "true" : "false"); }
        auto operator()(const char* s) { return util::escapeUTF8(s); }
        auto operator()(double d) { return util::fmt("%.6f", d); }
        auto operator()(int i) { return util::fmt("%d", i); }
        auto operator()(int64_t i) { return util::fmt("%" PRId64, i); }
        auto operator()(const std::string& s) { return util::escapeUTF8(s); }
        auto operator()(const ID& id) { return id.str(); }
        auto operator()(const std::optional<uint64_t>& u) { return u ? util::fmt("%" PRIu64, *u) : "<not set>"; }
        auto operator()(unsigned int u) { return util::fmt("%u", u); }
        auto operator()(uint64_t u) { return util::fmt("%" PRIu64, u); }
    };

    return std::visit(Visitor(), v);
};

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
using Properties = std::map<std::string, node::PropertyValue>;

} // namespace node

/** Base class for all AST nodes. */
class Node {
public:
    virtual ~Node();

    /** Returns the node tag associated with the instance's class. */
    auto nodeTag() const { return _node_tags.back(); }

    /** Returns true if the node has a parent (i.e., it's part of an AST). */
    bool hasParent() const { return _parent; }

    /**
     * Returns a parent node, assuming the node is part of an AST.
     *
     * @param i level of the parent to return, counting from 1 for the immediate parent
     * @return parent node, or null if the requested parent does not exist
     */
    Node* parent(int i = 1) const {
        if ( i == 0 )
            return nullptr;

        Node* p = _parent;
        for ( ; p && i > 1; i-- )
            p = p->_parent;

        return p;
    }

    /**
     * Returns the first parent node of a give type.
     *
     * @tparam T type of parent to search
     * @return parent node, or null if the requested parent does not exist
     */
    template<typename T>
    T* parent() const {
        if ( ! _parent )
            return nullptr;
        else if ( _parent->isA<T>() )
            return static_cast<T*>(_parent);
        else
            return _parent->parent<T>();
    }

    /**
     * Returns the length of the AST path to the current node from the AST's
     * root. If the node is part of an AST, returns a number >= 1. If it is not
     * (i.e., there's no parent node), returns 0.
     */
    auto pathLength() const {
        size_t i = 0;
        for ( auto n = parent(); n; i++, n = n->parent() )
            ;

        return i;
    }


    /** Returns the meta data associated with the node. */
    const auto& meta() const { return _meta; }

    /** Short-cut to return the location from the node's meta information. */
    const auto& location() const { return _meta.location(); }

    /** Sets the meta data associated with the node. */
    void setMeta(Meta m) { _meta = std::move(m); }

    /**
     * Returns the scope associated with the node, if any. Returns null if no
     * scope has been created for the node yet.
     */
    auto scope() const { return _scope.get(); }

    /**
     * Returns the node's direct scope if already created, or creates one if it
     * hasn't yet. In the latter case, the new scope is permanently associated
     * with the node before being returned.
     */
    auto getOrCreateScope() {
        if ( ! _scope )
            _scope = std::make_unique<Scope>();

        return _scope.get();
    }

    /**
     * Removes any associated scope from the node. Afterwards, `scope()` will
     * return null again.
     */
    void clearScope() { _scope.reset(); }

    /**
     * Looks up an ID in the node's chain of scope, following HILTI's scoping and visibility rules.
     *
     * @param id id to look up
     * @param what description of what we're looking for, for error reporting
     * @return if found, a pair of the declaration the ID refers to plus the declarations canonical ID; if not found an
     * error message appropriate for reporting to the user
     */
    Result<std::pair<Declaration*, ID>> lookupID(const ID& id, const std::string_view& what) const;

    /**
     * Returns a flag indicating whether a scope lookup passing this node
     * shall find IDs in parent nodes as well. This flag is set by default.
     */
    bool inheritScope() const { return _inherit_scope; }

    /**
     * Sets a flag indicating whether a scope lookup passing this node
     * shall find IDs in parent nodes as well.
     *
     * @param inherit if true, scope lookup will continue in parent nodes
     */
    void setInheritScope(bool inherit) { _inherit_scope = inherit; }

    /**
     * Returns the C++-level type for the nodes' class. This should be only
     * used for for debugging purposes.
     **/
    std::string typename_() const { return _typename(); }

    /** Returns a globally unique numeric identifier for the node. */
    uintptr_t identity() const { return reinterpret_cast<uintptr_t>(this); }

    /** Returns the set of all children. */
    const auto& children() const { return _children; }

    /**
     * Returns a child.
     *
     * @tparam T type that the child nodes are assumed to (and must) have
     * @param i zero-based index of the child, in the order they were passed into the constructor and/or added
     * @return child casted to type `T`, or null if there's no child node at that index
     */
    template<typename T>
    T* child(unsigned int i) const {
        if ( i >= _children.size() )
            return nullptr;

        return _children[i] ? _children[i]->as<T>() : nullptr;
    }

    /**
     * Returns a child.
     *
     * @tparam T type that the child nodes are assumed to (and must) have
     * @param i zero-based index of the child, in the order they were passed into the constructor and/or added
     * @return child casted to type `T`, or null if there's no child node at that index
     */
    template<typename T>
    T* childTryAs(unsigned int i) const {
        if ( i >= _children.size() )
            return nullptr;

        return _children[i] ? _children[i]->tryAs<T>() : nullptr;
    }

    /**
     * Returns a child at given index inside the vector of all children. The order in that vector is determined  by
     * the order in which the children were passed into the constructor and/or added.
     *
     * @param i index of the child, with zero being the first
     * @return child at given index, or null if there's no child at that index
     **/
    Node* child(unsigned int i) const {
        if ( i >= _children.size() )
            return nullptr;

        return _children[i];
    }

    /**
     * Returns a subrange of children. The indices correspond to the order
     * children were passed into the constructor and/or added.
     *
     * @tparam T type that the child nodes are assumed to (and must) have
     * @param begin index of first child to include
     * @param end index of one beyond last child to include; a negative index for *end* counts Python-style from end of
     * list; if not given, all children from `start` to the end of the list are returned
     * @return range containing children from `start` to `end`
     */
    template<typename T>
    auto children(int begin, std::optional<int> end) const {
        end = _normalizeEndIndex(begin, end);
        if ( end )
            return hilti::node::Range<T>(_children.begin() + begin, _children.begin() + *end);
        else
            return hilti::node::Range<T>();
    }

    /**
     * Returns a subrange of children. The indices correspond to the order
     * children were passed into the constructor and/or added.
     *
     * @tparam T type that the child nodes are assumed to (and must) have
     * @param begin index of first child to include
     * @param end index of one beyond last child to include; a negative index for *end* counts Python-style from end of
     * list; if not given, all children from `start` to the end of the list are returned
     * @return range containing children from `start` to `end`
     */
    template<typename T>
    auto children(int begin, std::optional<int> end) {
        end = _normalizeEndIndex(begin, end);
        if ( end )
            return hilti::node::Range<T>(_children.begin() + begin, _children.begin() + *end);
        else
            return hilti::node::Range<T>();
    }

    /**
     * Returns a subset of children selected by their type.
     *
     * @tparam T type of children to return
     * @return set of all children that have type `T`
     */
    template<typename T>
    node::Set<T> childrenOfType() const {
        typename hilti::node::Set<T> n;
        for ( auto c = _children.begin(); c != _children.end(); c = std::next(c) ) {
            if ( ! *c )
                continue;

            if ( auto t = (*c)->tryAs<T>() )
                n.push_back(t);
        }

        return n;
    }

    /**
     * Adds a child node. The node will be appended to the end of the current
     * list of children, and its parent will be set to the current node. If the
     * node already has a parent, it will be deep-copied first, and the new
     * instance will be added instead of the once passed in. ×
     *
     * @param ctx current context in use
     * @param n child node to add; it's ok for this to be null to leave a child slot unset
     */
    void addChild(ASTContext* ctx, Node* n) {
        if ( ! n ) {
            _children.emplace_back(nullptr);
            return;
        }

        n = _newChild(ctx, n);

        if ( ! n->location() && _meta.location() )
            n->setMeta(_meta);

        _children.emplace_back(n);
        _children.back()->_parent = this;
    }

    /**
     * Adds a series of child nodes. This operates like calling `addChild()` on
     * each of them individually.
     *
     * @param ctx current context in use
     * @param children nodes to add
     */
    void addChildren(ASTContext* ctx, const Nodes& children) {
        for ( auto&& n : children )
            addChild(ctx, n);
    }

    /**
     * Removes a child from the node. It's parent will be set back to null.
     * Does nothing if the child isn't found.
     *
     * @param n child node to remove
     */
    void removeChild(Node* n) {
        if ( ! n )
            return;

        if ( auto i = std::find(_children.begin(), _children.end(), n); i != _children.end() ) {
            (*i)->_parent = nullptr;
            _children.erase(i);
        }
    }

    /**
     * Removes a range of children from the node. They nodes won't be destroyed
     * but their parents will be reset back to null.
     *
     * @param begin index of first child to remove
     * @param end index of one beyond last child to include; a negative index for *end* counts Python-style from end of
     * list; if not given, all children from `start` to the end of the list are returned
     */
    void removeChildren(int begin, std::optional<int> end) {
        end = _normalizeEndIndex(begin, end);
        if ( ! end )
            return;

        auto end_ = _children.begin() + *end;
        for ( auto i = _children.begin() + begin; i < end_; i++ ) {
            if ( *i )
                (*i)->_parent = nullptr;
        }

        _children.erase(_children.begin() + begin, end_);
    }

    /**
     * Sets the child at a particular index. Its parent will be set to the
     * current node. If  the node already has a parent, it will be deep-copied
     * first, and the new instance will be added instead of the once passed in.
     * If there's an existing child at that index, it'll be removed first and
     * it's parent cleared.
     *
     * @param ctx current context in use
     * @param idx index of child to set
     * @param n child node to set; this may be null to unset the particular index
     */
    void setChild(ASTContext* ctx, size_t idx, Node* n) {
        if ( n ) {
            n = _newChild(ctx, n);

            if ( ! n->location() && _meta.location() )
                n->setMeta(_meta);
        }

        if ( _children[idx] )
            _children[idx]->_parent = nullptr;

        _children[idx] = n;

        if ( _children[idx] )
            _children[idx]->_parent = this;
    }

    /**
     * Replaces *all* children with a new set children. The function operates
     * like first removing all children, and then adding all the new ones in
     * the same order, with the same semantics for parent pointering and
     * deep-copying as adding/removing individual children exhibits.
     *
     * @param ctx current context in use
     * @param children new children to set
     */
    void replaceChildren(ASTContext* ctx, const Nodes& children);

    /**
     * Replaces a single child with a new one. The old one is removed, and the
     * new one is then stored at the old one's index. Semantics for parent
     * pointering and deep-copying are the same as removing/adding individual
     * children.
     *
     * @param ctx current context in use
     * @param old child to replace, which must exist (otherwise the method will abort with an internal error)
     * @param new_ new child to replace *old* with
     */
    void replaceChild(ASTContext* ctx, Node* old, Node* new_);

    /** Returns true if a node is of a particular type (class). */
    template<typename T>
    bool isA() const {
#ifndef NDEBUG
        _checkCast<T>(false);
#endif
        return (T::NodeLevel < _node_tags.size() && T::NodeTag == _node_tags[T::NodeLevel]);
    }

    /**
     * Casts a node into a particular class. The cast must be a valid C++
     * dynamic pointer cast, otherwise execution will abort with an internal error.
     */
    template<typename T>
    T* as() const {
#ifndef NDEBUG
        _checkCast<T>(true);
#endif
        return static_cast<const T*>(this);
    }

    /**
     * Casts a node into a particular class. The cast from the node to the
     * target type must be valid. If it isn't, in release builds, the call will
     * result in undefined behavior (and probably crash). In debug builds,
     * we'll catch invalid cases and abort with an internal error.
     */
    template<typename T>
    T* as() {
#ifndef NDEBUG
        _checkCast<T>(true);
#endif
        return static_cast<T*>(this);
    }

    /**
     * Attempts to casts a node into a particular class. Returns a nullptr if
     * the cast failed.
     */
    template<typename T>
    const T* tryAs() const {
#ifndef NDEBUG
        _checkCast<T>(false);
#endif

        if ( isA<T>() )
            return static_cast<const T*>(this);
        else
            return nullptr;
    }

    /**
     * Attempts to casts a node into a particular class. Returns a nullptr if
     * the cast failed.
     */
    template<typename T>
    T* tryAs() {
#ifndef NDEBUG
        _checkCast<T>(false);
#endif
        if ( isA<T>() )
            return static_cast<T*>(this);
        else
            return nullptr;
    }

    /**
     * Alternate version to attempt casting a node into a particular class.
     * Returns a nullptr if the cast failed. This version skips any potential
     * internal consistency checks, which can be helpful in case of false
     * positives. You should normally avoid using this unless absolutely
     * necessary.
     */
    template<typename T>
    const T* tryAs_() {
        if ( isA<T>() )
            return static_cast<const T*>(this);
        else
            return nullptr;
    }

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
     * children. Note that this can be called from inside a debugger.
     */
    std::string print() const;

    /** Renders the node as HILTI source code (same as `print()`) */
    operator std::string() const { return print(); }

    /**
     * Returns an internal string representation of the node and all its
     * children. Note that this can be called from inside a debugger.
     */
    std::string dump() const;

    /**
     * Returns an internal string representation of the node itself, excluding
     * its children.
     *
     * @param include_location if true, include source code locations into
     * the output
     */
    std::string renderSelf(bool include_location = true) const;

    /**
     * Associates an error message with the node. The error's location will be
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
     * Associates an error message with the node. The error's location will be
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
     * Associates an error message with the node. The error will have normal
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
     * Associates an error message with the node.
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

        _errors.emplace_back(std::move(error));
    }

    /** Returns true if there are any errors associated with the node. */
    bool hasErrors() const { return _errors.size(); }

    /** Returns any error messages associated with the node. */
    const auto& errors() const { return _errors; }

    /** Clears any error message associated with the node. */
    void clearErrors() { _errors.clear(); }

    /**
     * Removes all children from the node. It doesn't destroy the children,
     * pointers remain valid, it just unlinks them from their current parent.
     */
    void clearChildren();

    /**
     * Returns any instance properties associated with the node. These are used
     * (only) for debug logging. Derived classes should override this to add
     * any properties they retain inside internal node member variables.
     */
    virtual node::Properties properties() const { return {}; }

    /** Dispatch for the visitor API. */
    virtual void dispatch(visitor::Dispatcher& v) = 0;

    /**
     * Optional tag associated with the AST subbranch that this node is the top
     * of. If a tag is returned, this may be used to by visitors to skip the
     * subbranch entirely based on that tag.
     *
     * @return tag associated with the subbranch, or an empty string if none
     */
    virtual std::string_view branchTag() const { return ""; }

    Node& operator=(const Node& other) = delete;
    Node& operator=(Node&& other) noexcept = delete;

    static constexpr uint16_t NodeLevel = 0; // distance from `Node` in the inheritance hierarchy
    static constexpr ::hilti::node::Tag NodeTag = ::hilti::node::tag::Node;     // this class' node tag
    static constexpr ::hilti::node::Tags NodeTags = {::hilti::node::tag::Node}; // this class' inheritance path

protected:
    /**
     * Constructor initializing the node with children and meta data. The
     * semantics for the children's parent pointering and potential
     * deep-copying are the same as if they were added individually through
     * `addChild()`.
     *
     * @param ctx current context in use
     * @param children child nodes to add initially
     */
    Node(ASTContext* ctx, node::Tags node_tags, Nodes children, Meta meta)
        : _node_tags(node_tags), _meta(std::move(meta)) {
        assert(! _node_tags.empty());
        _children.reserve(children.size());
        for ( auto&& c : children ) {
            if ( c ) {
                c = _newChild(ctx, c);
                assert(! c->_parent);
                c->_parent = this;
            }

            _children.push_back(c);
        }
    }

    /** Constructor initializing the node with meta data but no children. */
    Node(ASTContext* ctx, node::Tags node_tags, Meta meta) : _node_tags(node_tags), _meta(std::move(meta)) {
        assert(! _node_tags.empty());
    }

    Node(Node&& other) = default;

    /**
     * Copy constructor. This copies only meta data and internal flags, but not
     * any children. The parent of the copied node will be unset.
     *
     * Use `node::deepcopy()` to fully copy a node.
     *
     */
    Node(const Node& other) : _node_tags(other._node_tags) {
        _meta = other._meta;
        _inherit_scope = other._inherit_scope;
        _parent = nullptr;

        // Don't copy children. We can't copy the pointers because that would
        // produce messed up parent pointers. And we can't deep copy here
        // because we don't have the context. That's all ok because this isn't
        // public anyways; to run this one needs to go through Node's cloning
        // functions.
    }

    /**
     * Returns the C++-level class name for the node's type. This is for
     * internal use only. It's the virtual backend to `typename_()`, which is
     * the one to call instead of this method.
     */
    virtual std::string _typename() const { return util::typename_(*this); }

    /**
     * Performs a shallow copy. A new instance of the current node class is
     * created and initialized with copies of all attributes and children with
     * latter being copied just by reference. This is for internal use only,
     * use node::deepcopy() to fully clone nodes.
     */
    virtual Node* _clone(ASTContext* ctx) const = 0; // shallow copy

    /**
     * Returns additional information to include into the node's `dump()`
     * output, as provided by derived classes.
     */
    virtual std::string _dump() const { return ""; }

private:
    friend Node* node::detail::deepcopy(ASTContext* ctx, Node* n, bool force);

    // Prepares a node for being added as a child, deep-copying it if it
    // already has a parent.
    static Node* _newChild(ASTContext* ctx, Node* child);

    // Clears the node's parent pointer.
    void _clearParent() { _parent = nullptr; }

    // Do Python-style array indexing with negative indices.
    std::optional<int> _normalizeEndIndex(int begin, std::optional<int> end) const {
        if ( end && *end < 0 )
            end = static_cast<int>(_children.size()) + *end;

        if ( ! end )
            end = _children.size();

        if ( end > begin )
            return *end;
        else {
            // Some versions of GCC diagnose a maybe uninitialized variable
            // here. Since we just return an unset optional, this should not be
            // possible. (pragmas copied from intrusive-ptr.h, where there's a
            // similar issue.)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
            return {};
#pragma GCC diagnostic pop
        }
    }

#ifndef NDEBUG
    // Checks casts for common mistakes.
    //
    // @param enforce_success if true, we'll abort if the cast fails due to a type mismatch
    template<typename T>
    void _checkCast(bool enforce_success) const {
        // Ensure that our RTTI information yields the same `isA<>` result as
        // the C++ type system.
        auto ours = (T::NodeLevel < _node_tags.size() && T::NodeTag == _node_tags[T::NodeLevel]);
        auto theirs = (dynamic_cast<const T*>(this) != nullptr);

        if ( ours != theirs ) {
            std::cerr << util::fmt("internal error: Node::_checkCast() RTTI mismatch\n")
                      << util::fmt("isA<T=%s>(%s) -> %s but dynamic_cast() says %s\n", typeid(T).name(), _typename(),
                                   ours ? "true" : "false", theirs ? "true" : "false")
                      << util::fmt("T::type_level=%" PRIu16 " T::node_tags={%s} this->types={%s}\n", T::NodeLevel,
                                   node::to_string(T::NodeTags), node::to_string(_node_tags));
            abort();
        }

        if ( enforce_success && ! ours ) {
            std::cerr << util::fmt("internal error: unexpected type, want %s but have %s\n", util::typename_<T>(),
                                   _typename());
            abort();
        }

        // Debugging helper: If `this` is a `QualifiedType`, it's virtually
        // always wrong to try casting it into a class derived from
        // `UnqualifiedType`. Most likely that's meant to instead cast
        // `this->type()`. We abort here to make debugging such problems
        // easier.
        if ( std::is_base_of_v<UnqualifiedType, T> && ! std::is_same_v<UnqualifiedType, T> )
            _checkCastBackend();
    }
#endif

    // Helper for _checkCast() to spot unexpected casts from `QualifiedType`.
    void _checkCastBackend() const;

    const node::Tags _node_tags; // inheritance path for the node
    Node* _parent = nullptr;     // parent node inside the AST, or null if not yet added to an AST
    Nodes _children;             // set of child nodes
    Meta _meta;                  // meta information associated with the node

    bool _inherit_scope = true;              // flag controlling whether scope lookups should continue in parent nodes
    std::unique_ptr<Scope> _scope = nullptr; // scope associated with the node, or null if non (i.e., scope is empty)
    std::vector<node::Error> _errors;        // errors associated with the node
};

namespace node {

/**
 * Mix-in class for nodes that need a globally unique ID identifying it. The ID
 * is retained across copies of the node.
 */
class WithUniqueID {
public:
    /**
     * Returns an ID that's unique for this node. The ID is
     * retained across copies of the node.
     */
    ID uniqueID() const { return _id; }

    /** Helper to call from the main node's properties() method. */
    node::Properties properties() const { return {{"unique_id", _id}}; }

    WithUniqueID() = delete;
    WithUniqueID(const WithUniqueID& other) = default;
    WithUniqueID(WithUniqueID&& other) = default;
    ~WithUniqueID() = default;

    WithUniqueID& operator=(const WithUniqueID& other) = default;
    WithUniqueID& operator=(WithUniqueID&& other) = default;

protected:
    /**
     *
     * Constructor for derived classes.
     *
     * @param prefix prefix to use for the ID, used just for readability of the
     * generated IDs
     */
    WithUniqueID(const char* prefix) : _id(util::fmt("%s_%" PRIu64, prefix, _id_counter++)) {}

private:
    ID _id;

    inline static uint64_t _id_counter = 0;
};

/** Mix-in class for nodes storing doc strings. */
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

/** Helper to handle visitor cycles loops. */
class CycleDetector {
public:
    void recordSeen(const Node* n) { _seen.insert(n); }
    bool haveSeen(const Node* n) const { return _seen.find(n) != _seen.end(); }

private:
    std::unordered_set<const Node*> _seen;
};

/**
 * Creates `Node` instances for a vector of objects all implementing the
 * `Node` interface.
 */
template<typename T>
Nodes flatten(std::vector<T> t) {
    Nodes v;
    v.reserve(t.size());
    for ( const auto& i : t )
        v.emplace_back(std::move(i));

    return v;
}

/**
 * Copies a ramge of nodes over into a vector. Note that as with all copies of
 * node, this performs shallow copying.
 */
template<typename T>
Nodes flatten(hilti::node::Range<T> t) {
    Nodes v;
    v.reserve(t.size());
    for ( const auto& i : t )
        v.emplace_back(std::move(i));

    return v;
}

/** Create a 1-element vector of nodes for an object implementing the `Node` API. */
template<typename T = Node*>
inline Nodes flatten(Node* n) {
    return {n};
}

/** Create a 1-element vector of nodes for an object implementing the `Node` API. */
template<typename T>
inline Nodes flatten(T* n) {
    return {std::move(n)};
}

/** Create a 1-element vector of nodes for a nullptr. */
template<typename T = std::nullptr_t>
inline Nodes flatten(std::nullptr_t) {
    return {nullptr};
}

/** Create an empty nodes list. */
inline Nodes flatten() { return Nodes(); }

/**
 * Creates `Node` instances for objects all implementing the `Node`
 * interface.
 */
template<typename T, typename... Ts, std::enable_if_t<(0 != sizeof...(Ts))>* = nullptr>
Nodes flatten(T t, Ts... ts) {
    return util::concat(std::move(flatten(t)), flatten(std::move(ts)...));
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
            y.push_back(i);
    }

    return y;
}

/**
 * Applies a function to each element of a node range, returning a new vector
 * with the results.
 */
template<typename X, typename F>
auto transform(const hilti::node::Range<X>& x, F f) {
    using Y = std::invoke_result_t<F, X*>;
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
    using Y = std::invoke_result_t<F, X*>;
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

} // namespace hilti

inline hilti::node::Properties operator+(hilti::node::Properties p1, hilti::node::Properties p2) {
    p1.merge(p2);
    return p1;
}
