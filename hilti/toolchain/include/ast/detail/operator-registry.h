// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <utility>
#include <vector>

#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/expressions/unresolved-operator.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/types/struct.h>

namespace hilti::operator_ {

/** Singleton registering available operators. */
class Registry {
public:
    using OperatorMap = std::map<Kind, std::vector<Operator>>;

    /** Returns a map of all available operators. */
    const auto& all() const { return _operators; }

    /** Returns a map of all available operators. */
    const auto& allOfKind(Kind kind) const { return _operators.at(kind); }

    /** Registers an Operator as available. */
    void register_(Kind kind, Operator info) { _operators[kind].push_back(std::move(info)); }

    void printDebug() {
#if 0
        // Can't print this at registratin time as that's happening through
        // global constructors.
        for ( auto a : _operators ) {
            for ( const auto& info : a.second ) {
                int status;
                auto n = abi::__cxa_demangle(info.typename_().c_str(), nullptr, nullptr, &status);
                HILTI_DEBUG(logging::debug::Overloads, hilti::util::fmt("registered %s for operator '%s'", (n ? n : info.typename_().c_str()), to_string(info.kind())));
            }
        }
#endif
    }

    /** Returns a singleton instance of the current class.  */
    static auto& singleton() {
        static Registry instance;
        return instance;
    }

private:
    OperatorMap _operators;
};

/** Helper class to register an operator on instantiation. */
class Register {
public:
    Register(Kind k, Operator c) { Registry::singleton().register_(k, std::move(c)); }
};

inline const auto& registry() { return Registry::singleton(); }

} // namespace hilti::operator_
