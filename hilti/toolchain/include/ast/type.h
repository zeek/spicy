// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <unistd.h>

#include <memory>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/id.h>
#include <hilti/ast/node.h>
#include <hilti/ast/visitor.h>

namespace hilti {

namespace builder {
class NodeBuilder;
}

namespace declaration {
class Parameter;
class Type;
} // namespace declaration

namespace type::function {
using Parameter = declaration::Parameter;
} // namespace type::function

namespace type {

/** Strong type argument for type constructors. */
struct Wildcard {
    explicit Wildcard() = default;
};

/** Strong type argument to `Unification` constructor. */
struct NeverMatch {
    explicit NeverMatch() = default;
};

namespace detail {
using ResolvedState = std::unordered_set<uintptr_t>;
}

} // namespace type

namespace type {

/**
 * Represent a type's unification string. Two types with the same unification
 * string are considered equivalent during AST processing.
 */
struct Unification {
    /** Creates a unset unification string, which will never match any other. */
    Unification() = default;

    /**
     * Create a unification from a pre-computed serialization string.
     *
     * @param serialization string representation of the unification; must not be empty
     */
    Unification(std::string serialization) : _serialization(std::move(serialization)) {
        assert(! _serialization->empty());
    }

    /**
     * Create a unification that's guaranteed to never match any other unification.
     *
     * @param never_match unused
     */
    Unification(NeverMatch _) : _serialization("") {}

    Unification(const Unification& other) = default;
    Unification(Unification&& other) = default;
    ~Unification() = default;

    Unification& operator=(const Unification& other) = default;
    Unification& operator=(Unification&& other) = default;

    /**
     * Returns a string representation of the unification string. This is
     * human-readable for display purposes.
     */
    std::string str() const {
        if ( ! _serialization.has_value() )
            return "<unset>";

        if ( _serialization->empty() )
            return "<never-match>";

        return *_serialization;
    }

    /** Forwards to `str()`. */
    operator std::string() const { return str(); }

    /** Returns true if unification string has been set. */
    operator bool() const { return _serialization.has_value(); }

private:
    friend bool operator==(const Unification& u1, const Unification&);
    friend bool operator!=(const Unification& u1, const Unification&);
    std::optional<std::string> _serialization; // set but empty means never-match
};

/**
 * Returns true if two unifications are equivalent. Will always return
 * false if any of the is set to never-match, or not set at all.
 */
inline bool operator==(const Unification& u1, const Unification& u2) {
    if ( ! (u1._serialization.has_value() && u2._serialization.has_value()) )
        return false;

    if ( u1._serialization->empty() || u2._serialization->empty() )
        return false;

    return *u1._serialization == *u2._serialization;
}

inline bool operator!=(const Unification& u1, const Unification& u2) { return ! (u1 == u2); }

} // namespace type


namespace type {
/**
 * Follows any `type::Name` reference chains to the actual, eventual type.
 *
 * Note that you will rarely need to call this function manually because
 * `QualifiedType::type()` follows type chains automatically by default. Doing
 * it that way is always preferred to calling `follow()` manually.
 *
 * @returns The eventual type found at the end of the chain. If there's not
 * `type::Name` encountered,  that's `t` itself. If a `type::Name` is
 * encountered that has not been resolved yet, returns that `type::Name` itself.
 */
extern UnqualifiedType* follow(UnqualifiedType* t);

} // namespace type

/** * Base class for classes implementing unqualified types. */
class UnqualifiedType : public Node {
public:
    /**
     * Returns the index the AST context associates with the type. This may
     * become set during AST resolving. If not set yet, returns `None`.
     */
    auto typeIndex() const { return _type_index; }

    /**
     * Returns the index the AST context associates with the declaration
     * declaring this type. This may become set during AST resolving. If not
     * set yet, returns `None`.
     */
    auto declarationIndex() const { return _declaration_index; }

    /**
     * Sets the type's declaration index that the context maintains. Note that
     * this does not update any state inside the context, so ensure setting it
     * to something valid.
     *
     * @param index index to set
     */
    void setDeclarationIndex(ast::DeclarationIndex index) {
        assert(index);
        _declaration_index = index;
    }

    /**
     * Returns the declaration declaring this type, or null if none. This is a
     * shortcut for retrieving the `decclarationIndex()` and then looking it up
     * in the AST context. That means, the index must have been set for this to
     * return anything.
     */
    declaration::Type* typeDeclaration() const;

    /**
     * Returns the C++ ID associated with this type, if any. This is a shortcut
     * to retrieving the associated declaration's C++ ID, which is set through
     * a `&cxxname` attribute.
     */
    ID cxxID() const;

    /**
     * Returns the ID associated with this type, if any. This is a shortcut to
     * retrieving the associated declaration's fully-qualified ID, if
     * available.
     */
    ID typeID() const;

    /**
     * Returns the canonical ID associated with this type, if any. This is a
     * shortcut to retrieving the associated declaration's canonical ID, if
     * available.
     */
    ID canonicalID() const;

    /**
     * Returns true if the type is a wildcard type. That means that all other
     * instances of the same type class coerce into this type, independent of
     * any further parameters or other AST child nodes. In HILTI source code,
     * this typically corresponds to a type `T<*>`.
     */
    bool isWildcard() const { return _is_wildcard; }

    /** Returns the type's current unification string. */
    const auto& unification() const { return _unification; }

    /**
     * Returns true if the type was declaraed with the `&on-heap` attribute
     * set. This requires the type to have a `declarationIndex()` already,
     * otherwise it will default to false.
     */
    bool isOnHeap() const;

    /**
     * Attempts to set the type unification string for this type. If it can't
     * be set (yet), returns false. If it's already set, returns true without
     * changing anything.
     */
    bool unify(ASTContext* ctx, Node* scope_root = nullptr);

    /**
     * Sets the type's unification string explicitly. Should normally be called
     * only by the type unifier.
     *
     * @param u unification string to set
     */
    void setUnification(type::Unification u) { _unification = std::move(u); }

    /**
     * Clears any previously set unification string. It will be recomputed next
     * time the type unifier runs.
     */
    void clearUnification() { _unification = {}; }

    /**
     * Returns a static string that's descriptive and unique for all instances
     * of this type class. This is used to determine whether two types are of
     * the same class when comparing them for equality.
     */
    virtual std::string_view typeClass() const = 0;

    /**
     * For deferenceable types, returns the type of dereferenced elements.
     * Returns null for all other types.
     */
    virtual QualifiedType* dereferencedType() const { return {}; }

    /**
     * For container types, returns the type of elements. Returns null for all
     * other types.
     */
    virtual QualifiedType* elementType() const { return {}; }

    /**
     * For iterable types, returns the type of an iterator. Returns null for
     * all other types.
     */
    virtual QualifiedType* iteratorType() const { return {}; }

    /** Returns any parameters the type expects on construction. */
    virtual hilti::node::Set<type::function::Parameter> parameters() const { return {}; }

    /**
     * For viewable types, returns the type of a view. Returns null for all
     * other types.
     */
    virtual QualifiedType* viewType() const { return {}; }

    /**
     * Returns true if the data behind a value of this type could be aliased by
     * another value.
     */
    virtual bool isAliasingType() const { return false; }

    /** Returns true for types that can be used to instantiate variables. */
    virtual bool isAllocable() const { return false; }

    /** Returns true for types for which values can be modified after creation. */
    virtual bool isMutable() const { return false; }

    /** Returns true for types that are compared by name, not structurally. */
    virtual bool isNameType() const { return false; }

    /** Returns true for HILTI types that implement a reference to another type. */
    virtual bool isReferenceType() const { return false; }

    /** * Returns true if a type is fully resolved. */
    virtual bool isResolved(node::CycleDetector* cd = nullptr) const { return true; }

    /** Returns true for HILTI types that can be compared for ordering at runtime. */
    virtual bool isSortable() const { return false; }

    /**
     * For internal use. Called when an unqualified type has been embedded into
     * a qualified type, allowing the former to adjust for constness if
     * necessary.
     *
     * @param qtype the qualified type now embedding this type
     */
    virtual void newlyQualified(const QualifiedType* qtype) const {}

    hilti::node::Properties properties() const override;

protected:
    friend class ASTContext;
    friend UnqualifiedType* hilti::type::follow(UnqualifiedType* t);

    UnqualifiedType(ASTContext* ctx, node::Tags node_tags, type::Unification&& u, Meta meta)
        : Node::Node(ctx, node_tags, std::move(meta)), _context(ctx), _unification(std::move(u)) {}
    UnqualifiedType(ASTContext* ctx, node::Tags node_tags, type::Unification&& u, Nodes children, Meta meta)
        : Node::Node(ctx, node_tags, std::move(children), std::move(meta)), _context(ctx), _unification(std::move(u)) {}
    UnqualifiedType(ASTContext* ctx, node::Tags node_tags, type::Wildcard _, type::Unification&& u, Meta meta)
        : Node::Node(ctx, node_tags, {}, std::move(meta)),
          _context(ctx),
          _unification(std::move(u)),
          _is_wildcard(true) {}
    UnqualifiedType(ASTContext* ctx, node::Tags node_tags, type::Wildcard _, type::Unification&& u, Nodes children,
                    Meta meta)
        : Node::Node(ctx, node_tags, std::move(children), std::move(meta)),
          _context(ctx),
          _unification(std::move(u)),
          _is_wildcard(true) {}

    // Returns the AST context that this type is part of.
    auto context() const { return _context; }

    // For the AST context to set the declaration index.
    void setTypeIndex(ast::TypeIndex index) {
        assert(index);
        _type_index = index;
    }

    /** Implements `Node` interface. */
    std::string _dump() const override;

    HILTI_NODE_0(UnqualifiedType, override);

private:
    ASTContext* _context;

    type::Unification _unification;           // types unification string if known yet
    bool _is_wildcard = false;                // true if types is presenting a wildcard type
    ast::TypeIndex _type_index;               // type index associated with the type, if any
    ast::DeclarationIndex _declaration_index; // type index associated with the type, if any
};

/** Selects left-hand-side or right-hand-side semantics for an expression. */
enum class Side { LHS, RHS };

/** Selects constant or non-constant semantics for an expression. */
enum class Constness { Const, Mutable };

/** AST node presenting a type along with associated constness and RHS/LHS semantics. */
class QualifiedType : public Node {
public:
    /**
     * Returns the underlying type. By default, this follows any `type::Name` references.
     *
     * @param follow if true, follows any `type::Name` references to the actual type
     */
    UnqualifiedType* type(bool follow = true) const { return follow ? type::follow(_type()) : _type(); }

    /** Returns true if the qualified type is constant. */
    bool isConstant() const { return _constness == Constness::Const; }

    /**
     * Returns true if the type was created through `createExternal()`. If so,
     * `type()` will retrieve the external type.
     */
    auto isExternal() const { return static_cast<bool>(_external); }

    /** Returns the type's constness. */
    auto constness() const { return _constness; }

    /**
     * Returns true if the underlying unqualified type is fully resolved. This
     * method recurses through any subtypes (but avoids getting tripped up by
     * cycles).
     */
    bool isResolved(node::CycleDetector* cd = nullptr) const;

    /** Returns true if the type is a wildcard type. */
    bool isWildcard() const { return _type()->isWildcard(); }

    /** Returns true if the type is `auto`. */
    bool isAuto() const;

    /** Returns the type's "sideness". */
    auto side() const { return _side; }

    /** Shortcut to try-cast to `type::Name`. */
    type::Name* alias() const;

    /**
     * Extracts the innermost type, removing any wrapping in reference or
     * iterator types recursively.
     */
    QualifiedType* innermostType();

    /**
     * Sets the constness of the type.
     *
     * @param const new constness of type
     */
    void setConst(Constness constness) { _constness = constness; }

    /**
     * Sets the type's "sideness".
     *
     * @param side new "sideness" of type
     */
    void setSide(Side side) { _side = side; }

    /** Implements `Node` interface. */
    hilti::node::Properties properties() const override;

    /**
     * Factory method.
     *
     * @param ctx context to use
     * @param t underlying type to wrap
     * @param const constness of type
     * @param m meta data to attach
     */
    static auto create(ASTContext* ctx, UnqualifiedType* t, Constness const_, Meta m = Meta()) {
        if ( ! m )
            m = t->meta();

        auto* qt = ctx->make<QualifiedType>(ctx, Nodes{t}, const_, Side::RHS, std::move(m));
        qt->type()->unify(ctx);
        qt->_type()->newlyQualified(qt);
        return qt;
    }

    /**
     * Factory method.
     *
     * @param ctx context to use
     * @param t underlying type to wrap
     * @param const constness of type
     * @param side the type's "sideness"
     * @param m meta data to attach
     */
    static auto create(ASTContext* ctx, UnqualifiedType* t, Constness const_, Side side, const Meta& m = Meta()) {
        auto* qt = ctx->make<QualifiedType>(ctx, Nodes{t}, const_, side, m);
        qt->type()->unify(ctx);
        qt->_type()->newlyQualified(qt);
        return qt;
    }

    /**
     * Factory method creating a qualified type linking directly to an already
     * existing unqualified type.
     *
     * This avoid copying the existing type over into a child, and can help to
     * breaks reference cycles.
     *
     * @param ctx context to use
     * @param t underlying type to wrap
     * @param const constness of type
     * @param m meta data to attach
     */
    static QualifiedType* createExternal(ASTContext* ctx, UnqualifiedType* t, Constness const_, const Meta& m = Meta());

    /**
     * Factory method creating a qualified type linking directly to an already
     * existing unqualified type.
     *
     * This avoid copying the existing type over into a child, and can help to
     * breaks reference cycles.
     *
     * @param ctx context to use
     * @param t underlying type to wrap
     * @param const constness of type
     * @param side the type's "sideness"
     * @param m meta data to attach
     */
    static QualifiedType* createExternal(ASTContext* ctx, UnqualifiedType* t, Constness const_, Side sideness,
                                         const Meta& m = Meta());

    /**
     * Shortcut to create a qualified type wrapping a `type::Auto` instance.
     * This sets sideness to RHS, and constness to false.
     */
    static QualifiedType* createAuto(ASTContext* ctx, const Meta& m = Meta());

    /**
     * Shortcut to create a qualified type wrapping a `type::Auto` instance.
     * This sets constness to false.
     */
    static QualifiedType* createAuto(ASTContext* ctx, Side side, const Meta& m = Meta());

    /** Factory method creating a copy of the type with "sideness" changed to LHS. */
    auto recreateAsLhs(ASTContext* ctx) const {
        if ( auto* t = _type(); t->isNameType() && (parent() || t->typeID()) )
            return QualifiedType::createExternal(ctx, t, Constness::Mutable, Side::LHS);
        else
            return QualifiedType::create(ctx, t, Constness::Mutable, Side::LHS);
    }

    /** Factory method creating a copy of the type with constness changed to constant. */
    auto recreateAsConst(ASTContext* ctx) const {
        if ( auto* t = _type(); t->isNameType() && (parent() || t->typeID()) )
            return QualifiedType::createExternal(ctx, t, Constness::Const, Side::RHS);
        else
            return QualifiedType::create(ctx, t, Constness::Const, Side::RHS);
    }

    /** Factory method creating a copy of the type with constness changed to non-constant. */
    auto recreateAsNonConst(ASTContext* ctx) const {
        if ( auto* t = _type(); t->isNameType() && (parent() || t->typeID()) )
            return QualifiedType::createExternal(ctx, t, Constness::Mutable, Side::RHS);
        else
            return QualifiedType::create(ctx, t, Constness::Mutable, Side::RHS);
    }

protected:
    friend class ASTContext;

    QualifiedType(ASTContext* ctx, Nodes children, Constness constness, Side side, Meta meta)
        : Node(ctx, NodeTags, std::move(children), std::move(meta)),
          _context(ctx),
          _constness(constness),
          _side(side) {}

    QualifiedType(ASTContext* ctx, Nodes children, UnqualifiedType* t, Constness constness, Side side, Meta meta)
        : Node(ctx, NodeTags, std::move(children), std::move(meta)),
          _context(ctx),
          _external(ctx->register_(t)),
          _constness(constness),
          _side(side) {}

    /** Implements `Node` interface. */
    std::string _dump() const final;

    HILTI_NODE_0(QualifiedType, final);

private:
    // Internal version of _type() that doesn't follow name references.
    UnqualifiedType* _type() const;

    ASTContext* _context; // context that the node is part of

    ast::TypeIndex _external; // for external types, the index of the type
    Constness _constness;
    Side _side = Side::RHS;
};

namespace type {

/**
 * Returns true if a type is fully resolved. This asks the type's `isResolved`
 * handler whether it considers itself resolved.
 */
inline bool isResolved(UnqualifiedType* t) { return t->isResolved(); }

/**
 * Returns true if a qualified type's wrapped type is fully resolved. This asks
 * the type's `isResolved` handler whether it considers itself resolved.
 */
inline bool isResolved(QualifiedType* t) { return isResolved(t->type()); }

/**
 * Returns true if two types are semantically equal. This returns true only if
 * both types have been fully resolved already.
 */
inline bool same(UnqualifiedType* t1, UnqualifiedType* t2) {
    auto* t1_ = follow(t1);
    auto* t2_ = follow(t2);

    if ( t1_->unification() == t2_->unification() )
        return true;

    return false;
}

/**
 * Returns true if two types are semantically equal. This returns true only if
 * both types have been fully resolved already.
 */
inline bool same(QualifiedType* t1, QualifiedType* t2) {
    if ( t1->isConstant() != t2->isConstant() )
        return false;

    auto* t1_ = t1->type(); // performs follow
    auto* t2_ = t2->type(); // performs follow

    if ( t1_->unification() == t2_->unification() )
        return true;

    return false;
}

/**
 * Returns true if two types are semantically equal ignoring their constness.
 * This returns true only if both types have been fully resolved already.
 */
inline bool sameExceptForConstness(QualifiedType* t1, QualifiedType* t2) {
    if ( ! isResolved(t1) || ! isResolved(t2) )
        return false;

    auto* t1_ = t1->type(); // performs follow
    auto* t2_ = t2->type(); // performs follow

    if ( t1_->unification() == t2_->unification() )
        return true;

    if ( (t1_->isWildcard() || t2_->isWildcard()) && t1_->typeClass() == t2_->typeClass() )
        return true;

    return false;
}

} // namespace type
} // namespace hilti
