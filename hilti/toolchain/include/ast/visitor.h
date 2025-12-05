// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/node.h>
#include <hilti/ast/visitor-dispatcher.h>
#include <hilti/base/logger.h>

namespace hilti {

namespace visitor {

enum class Order { Pre, Post };

/** Iterator traversing all nodes of an AST. */
template<Order order>
class Iterator {
public:
    using value_type = Node*;

    Iterator() { _path.reserve(20); }
    Iterator(Node* root, bool include_empty, std::string_view limit_to_tag)
        : _include_empty(include_empty), _limit_to_tag(limit_to_tag) {
        _path.reserve(20);
        if ( root )
            _path.emplace_back(root, -1);
    }

    Iterator(const Iterator& other) = default;
    Iterator(Iterator&& other) noexcept = default;

    ~Iterator() = default;

    auto depth() const { return _path.size(); }

    Iterator& operator++() {
        _next();
        return *this;
    }

    Node* operator*() const { return _current(); }

    Iterator& operator=(const Iterator& other) = default;
    Iterator& operator=(Iterator&& other) noexcept = default;
    bool operator==(const Iterator& other) const { return _path == other._path; }
    bool operator!=(const Iterator& other) const { return ! (*this == other); }

private:
    struct Location {
        Node* node = nullptr;
        int child = -2;

        Location(Node* n, int c) : node(n), child(c) {}
        auto operator==(const Location& other) const {
            return std::pair(node, child) == std::pair(other.node, other.child);
        }
    };

    Node* _current() const {
        if ( _path.empty() )
            throw std::runtime_error("invalid reference of visitor's iterator");

        auto& p = _path.back();

        if ( ! p.node )
            return nullptr;

        if ( p.child < 0 ) {
            assert(order == Order::Pre);
            return p.node;
        }

        if ( p.child == static_cast<int>(p.node->children().size()) ) {
            assert(order == Order::Post);
            return p.node;
        }

        assert(p.child < static_cast<int>(p.node->children().size()));
        return p.node->children()[p.child];
    }

    void _next() {
        if ( _path.empty() )
            return;

        auto& p = _path.back();
        p.child += 1;

        if ( p.child == -1 ) {
            if ( order == Order::Pre )
                return;

            _next();
            return;
        }

        if ( ! p.node ) {
            _path.pop_back();
            _next();
            return;
        }

        assert(p.child >= 0);

        if ( p.child < static_cast<int>(p.node->children().size()) ) {
            auto child = p.node->children()[p.child];
            auto visit_child = (child || _include_empty); // don't visit null children

            if ( child && ! _limit_to_tag.empty() && ! child->branchTag().empty() &&
                 child->branchTag() != _limit_to_tag )
                visit_child = false;

            if ( visit_child )
                _path.emplace_back(child, -2);

            _next();
            return;
        }

        if ( p.child == static_cast<int>(p.node->children().size()) ) {
            if constexpr ( order == Order::Post )
                return;

            p.child += 1;
        }

        if ( p.child > static_cast<int>(p.node->children().size()) ) {
            _path.pop_back();
            _next();
            return;
        }
    }

    std::vector<Location> _path;
    bool _include_empty = false;
    std::string_view _limit_to_tag;
};

/** Range of AST nodes for traversal. */
template<Order order>
class Range {
public:
    using iterator_t = Iterator<order>;
    using value_type = typename Iterator<order>::value_type;
    Range(Node* root, std::string_view limit_to_tag) : _root(root), _limit_to_tag(limit_to_tag) {}

    auto begin(bool include_empty = false) {
        if constexpr ( order == Order::Pre )
            return iterator_t(_root, include_empty, _limit_to_tag);

        return ++iterator_t(_root, include_empty, _limit_to_tag);
    }

    auto end() { return iterator_t(); }

private:
    Node* _root = nullptr;
    std::string_view _limit_to_tag;
};

/**
 * Generic AST visitor.
 *
 * @tparam order order of iteration
 */
template<Order order, typename Dispatcher>
class Visitor : public Dispatcher {
public:
    using base_t = Visitor<order, Dispatcher>;
    using iterator_t = Iterator<order>;

    static const Order Order_ = order;

    Visitor() = default;
    virtual ~Visitor() = default;

    virtual void dispatch(Node* n) {
        if ( n )
            n->dispatch(*this);
    }
};

/**
 * Mix-in for an AST visitor that modifies the AST. This brings in some
 * additional helpers for modifying the AST.
 *
 * @param builder builder to use for modifications
 * @param dbg debug stream to log modifications to
 * @tparam order order of iteration
 */
class MutatingVisitorBase {
public:
    /**
     * Constructor.
     *
     * @param ctx AST context the nodes are part of.
     * @param dbg debug stream to log modifications to
     */
    MutatingVisitorBase(ASTContext* ctx, logging::DebugStream dbg);

    /** Returns the AST context the nodes are part of. */
    auto context() const { return _context; }

    /**
     * Returns true, if any modifications of the AST have been performed, or
     * registered, by this visitor.
     */
    auto isModified() const { return _modified; }

    /**
     * Sets the flag recording that modifications have taken place.
     *
     * This should only be used in rare cases; prefer `recordChange()` instead,
     * or `replaceNode()` if appropriate. Use this only if you have to go
     * around the visitor API for making AST changes directly, and note that
     * could then lead to the visitor's state tracking not learning about that
     * change.
     */
    void setModified() { _modified = true; }

    /** Clears the flag recording that modifications have taken place. */
    auto clearModified() { _modified = false; }

    /**
     * Replace a child node with a new node.
     *
     * When overriding, the parent's implementation should be called.
     *
     * @param old child node to replace
     * @param new_ new node to replace it with
     * @param msg debug message describing the change
     */
    virtual void replaceNode(Node* old, Node* new_, const std::string& msg = "");

    /**
     * Remove a node from the AST.
     *
     * When overriding, the parent's implementation should be called.
     *
     * @param old the node to be removed
     * @param msg debug message describing the change
     */
    virtual void removeNode(Node* old, const std::string& msg = "");

    /**
     * Records that an AST change has been performed. Call this *before* making
     * changes to AST node, but prefer using `replaceNode()` or `removeNode()`
     * instead when possible.
     *
     * When overriding, the parent's implementation should be called.
     *
     * @param old node that is about to be modified.
     * @param msg debug message describing the change
     */
    virtual void recordChange(const Node* old, const std::string& msg = "");

    /**
     * Records that an AST change has been performed. Call this after making a
     * change to an AST if both old and new/changed nodes are available (which
     * often isn't the case when making in-place changes; call the other variant of
     * `recordChange()` then instead *before* making the change). Prefer using
     * `replaceNode()` or `removeNode()` when possible.
     *
     * When overriding, the parent's implementation should be called.
     *
     * @param old node that is about to be modified.
     * @param changed node reflecting the change; it'll be rendered into the debug message, but not otherwise used
     * @param msg message being added to debug log message
     */
    virtual void recordChange(const Node* old, Node* changed, const std::string& msg = "");

protected:
    /**
     * Helper to retrieve the AST context from a HILTI builder. This method
     * exists only so that we can implement the lookup in the implementation
     * file, enabling derived, templated classes to perform it without needing
     * include `builder.h` in their header.
     */
    static ASTContext* contextFromBuilder(Builder* builder);

private:
    ASTContext* _context;
    logging::DebugStream _dbg;

    bool _modified = false;
};

template<Order order, typename Dispatcher, typename Builder>
class MutatingVisitor : public Visitor<order, Dispatcher>, public MutatingVisitorBase {
public:
    /**
     * Constructor.
     *
     * @param builder builder to use for modifications
     * @param dbg debug stream to log modifications to
     */
    MutatingVisitor(Builder* builder, const logging::DebugStream& dbg)
        : MutatingVisitorBase(contextFromBuilder(builder), dbg), _builder(builder) {}

    using visitor::MutatingVisitorBase::MutatingVisitorBase;

    /**
     * Returns a builder for modifications. This will be valid only if the
     * corresponding constructor was used, and return null otherwise.
     */
    auto builder() const { return _builder; }

private:
    Builder* _builder = nullptr; // may be null if not passed to constructor
};

} // namespace visitor

/**
 * Visitor performing a pre-order iteration over a HILTI AST.
 */
namespace visitor {
using PreOrder = visitor::Visitor<visitor::Order::Pre, visitor::Dispatcher>;

/**
 * Mutating visitor performing a pre-order iteration over a HILTI AST.
 */
using MutatingPreOrder = visitor::MutatingVisitor<visitor::Order::Pre, visitor::Dispatcher, Builder>;

/**
 * Iterator range traversing an AST in pre-order.
 */
using RangePreOrder = visitor::Range<visitor::Order::Pre>;

/**
 * Visitor performing a post-order iteration over a HILTI AST.
 */
using PostOrder = visitor::Visitor<visitor::Order::Post, visitor::Dispatcher>;

/**
 * Mutating visitor performing a post-order iteration over a HILTI AST.
 */
using MutatingPostOrder = visitor::MutatingVisitor<visitor::Order::Post, visitor::Dispatcher, Builder>;

/**
 * Iterator range traversing a HILTI AST in post-order.
 */
using RangePostOrder = visitor::Range<visitor::Order::Post>;

/** Return a range that iterates over AST, returning each node successively. */
template<typename Visitor, typename Node>
auto range(Visitor&& visitor, Node* root, std::string_view limit_to_tag = {}) {
    return visitor::Range<std::remove_reference<Visitor>::type::Order_>(root, limit_to_tag);
}

/** Walks the AST recursively and calls dispatch for each node. */
template<typename Visitor, typename Node>
auto visit(Visitor&& visitor, Node* root, std::string_view limit_to_tag = {}) {
    for ( auto i : range(visitor, root, limit_to_tag) )
        visitor.dispatch(i);

    return;
}

/** Walks the AST recursively and calls dispatch for each node, then runs callback and returns its result. */
template<typename Visitor, typename Node, typename ResultFunc>
auto visit(Visitor&& visitor, Node* root, std::string_view limit_to_tag, ResultFunc result) {
    for ( auto i : range(visitor, root, limit_to_tag) )
        visitor.dispatch(i);

    return result(visitor);
}

/** Dispatches a visitor for a single node. */
template<typename Visitor>
void dispatch(Visitor&& visitor, Node* n) {
    n->dispatch(visitor);
}

/** Dispatches a visitor for a single node, then runs a callback and returns its result. */
template<typename Visitor, typename ResultFunc>
auto dispatch(Visitor&& visitor, Node* node, ResultFunc result) {
    node->dispatch(visitor);
    return result(visitor);
}

} // namespace visitor
} // namespace hilti
