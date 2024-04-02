// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <list>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <hilti/ast/operator.h>

#define HILTI_OPERATOR(ns, cls)                                                                                        \
    Result<hilti::expression::ResolvedOperator*> instantiate(hilti::Builder* builder, Expressions operands, Meta meta) \
        const final {                                                                                                  \
        return {ns::operator_::cls::create(builder->context(), this, result(builder, operands, meta),                  \
                                           std::move(operands), meta)};                                                \
    }                                                                                                                  \
                                                                                                                       \
    std::string name() const final { return hilti::util::replace(#cls, "_::", "::"); }                                 \
    std::string _typename() const final { return hilti::util::typename_(*this); }

#define HILTI_OPERATOR_IMPLEMENTATION(cls)                                                                             \
    namespace {                                                                                                        \
    static hilti::operator_::Register<cls> _operator_##cls;                                                            \
    }

namespace hilti::operator_ {

/** Singleton registering available operators. */
class Registry {
public:
    /**
     * Returns all available built-on operators of kind function call matching
     * a given function name.
     */
    const auto& byBuiltinFunctionID(const ID& id) { return _operators_by_builtin_function[id]; }

    /**
     * Returns all available operators of a given kind.
     */
    const auto& byKind(Kind kind) { return _operators_by_kind[kind]; }

    /**
     * Returns all available operators of kind `member call` matching a given
     * method ID.
     */
    const auto& byMethodID(const ID& id) { return _operators_by_method[id]; }

    /** Returns all available operators of a given operator name. */
    const auto& byName(const std::string_view& name) { return _operators_by_name[std::string(name)]; }

    /**
     * Returns any function call operators defining a static name matching a
     * given unresolved operator.
     *
     * @param op unresolved operator to match against
     * @returns tuple where the 1st element is a boolean indicating if the
     * caller should proceed checking the candidates returned as the 2dn
     * element; if not, a match has been found but is valid for calling, and
     * hence the caller should abort resolution
     */
    std::pair<bool, std::optional<std::vector<const Operator*>>> functionCallCandidates(
        const expression::UnresolvedOperator* op);

    /** Returns all available operators. */
    const auto& operators() const { return _operators; }

    /**
     * Registers an operator with the registry. It will not immediately become
     * available but remain pending until initialized later.
     */
    void register_(std::unique_ptr<Operator> op);

    /**
     * Attempts to initialize all pending operators. Initialization will
     * succeed for all operators for which argument types can be fully resolved
     * at this time; these will then be available through the registry going
     * forward. Any operators that cannot be initialized yet will remain
     * pending and won't be available for lookup for the time being.
     *
     * @param builder builder to use for operator initialization
     */
    void initPending(Builder* builder);

    /** Returns true if any registered operators remain uninitialized. */
    bool havePending() const { return ! _pending.empty(); }

    /** Removes all registered operators, releasing their memory. */
    void clear();

    /**
     * Aborts with an internal error if any registered built-in operators
     * remain uninitialized. If this happens after an AST has otherwise be
     * fully resolved, something's wrong those operator definitions (like an
     * unknown type).
     */
    void debugEnforceBuiltInsAreResolved(Builder* builder) const;

    /** Returns a singleton instance of the current class.  */
    static auto& singleton() {
        static Registry instance;
        return instance;
    }

private:
    std::list<std::unique_ptr<Operator>> _pending;             // all registered, but not yet initialized operators
    std::vector<std::unique_ptr<Operator>> _operators;         // all initialized operators
    std::map<std::string, const Operator*> _operators_by_name; // initialized operators by name
    std::map<Kind, std::vector<const Operator*>> _operators_by_kind; // initialized operators by kind
    std::map<ID, std::vector<const Operator*>>
        _operators_by_builtin_function; // initialized operators by builtin call operators; empty ID collect all without
                                        // a static name
    std::map<ID, std::vector<const Operator*>> _operators_by_method; // initialized operators by method
};

/**
 * Retrieves an operator by name. Raises an internal error if there's no
 * operator available under that name.
 */
inline auto get(std::string_view name) {
    if ( auto op = Registry::singleton().byName(name) )
        return op;
    else
        logger().internalError(util::fmt("unknown operator '%s'", name));
}

/** Helper class to register an operator on instantiation. */
template<typename T>
class Register {
public:
    Register() { Registry::singleton().register_(std::make_unique<T>()); }
};

inline auto& registry() { return Registry::singleton(); }

} // namespace hilti::operator_
