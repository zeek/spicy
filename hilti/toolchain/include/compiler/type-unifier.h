// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>

#include <hilti/ast/forward.h>
#include <hilti/ast/node.h>

namespace hilti::type_unifier {

/**
 * Unifies all the unqualified types in an AST to the degree possible.
 *
 * @returns true if at least one type was unified that wasn't before.
 */
bool unify(Builder* builder, Node* node);

/**
 * Unifies an unqualified type, if possible. If it's already unified, no change
 * will be made.
 *
 * @returns true if either the type is now unified, either because it was
 * already or because it could be unified now.
 */
bool unify(ASTContext* ctx, UnqualifiedType* type);

/**
 * Checks whether types in the AST are fully unified. That means that all
 * relevant types must (1) have a type unification, and (2) that unification
 * must be up to date (i.e., re-computing produces the same value).
 *
 * @returns true if all types are fully unified.
 */
bool check(Builder* builder, ASTRoot* root);

/**
 * API class for implementing type unification for custom types by plugins.
 * This builds up a serialization string by adding its pieces successively.
 */
class Unifier {
public:
    /** Add the unification string for a given type. The processes the type recursively. */
    void add(UnqualifiedType* t);

    /** Add the unification string for a given type. The processes the type recursively. */
    void add(QualifiedType* t);

    /** Add a string to the current unification string. */
    void add(const std::string& s);

    /**
     * Signal an error, such as a subtype that cannot be unified yet.
     * Unification will abort and leave the type currently being unified in as
     * ununified.
     */
    void abort() { _abort = true; }

    /** Checks whether `abort()` has been called yet. */
    auto isAborted() const { return _abort; }

    /** Returns the current unification string. */
    const auto& serialization() const { return _serial; }

    /** Resets all state to start a new unification. */
    void reset() {
        _serial.clear();
        _cd.clear();
        _abort = false;
    }

private:
    std::string _serial;     // builds up serialization incrementally
    node::CycleDetector _cd; // used to check for invalid cycles
    bool _abort = false;     // if true, cannot compute serialization yet
};

namespace detail {
/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool unifyType(type_unifier::Unifier* unifier, UnqualifiedType* t);
} // namespace detail

} // namespace hilti::type_unifier
