// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cassert>
#include <string>

#include <hilti/rt/type-info.h>
#include <hilti/rt/types/reference.h>

namespace spicy::rt {

/**
 * Type-erased wrapper around parsed unit instances.
 *
 * Initially, this will be unbound, i.e., not refer to any particular
 * instance. `initialize()` then binds it to an instance and have
 * `ParsedUnit` hold a strong reference to it.
 */
class ParsedUnit : public hilti::rt::type_info::value::Parent {
public:
    /** Returns typed access to the contained instance. */
    template<typename T>
    const T& get() const {
        if ( auto p = _unit.as<T>() )
            return *p;
        else
            throw hilti::rt::NullReference("parsed unit not set");
    }

    /**
     * Returns the instance and its type in a value representation suitable
     * to use with the `type-info` API for iteration over the fields.
     */
    hilti::rt::type_info::Value value() const {
        if ( ! _ptr )
            throw hilti::rt::NullReference("parsed unit not set");

        assert(_ti);
        return {_ptr, _ti, *this};
    }

    /** Releases any contained instance. */
    void reset() {
        _unit.reset();
        _ptr = nullptr;
        _ti = nullptr;
    }

    /**
     * Initializes the wrapper with a particular parse unit instance. The
     * `ParsedUnit` will hold a strong reference to the instance until
     * released.
     *
     * @param u type-erased wrapper to initialize
     * @param t reference to instance to initialize `u` with
     * @param ti pointer to valid type information for `T`
     */
    template<typename T>
    static void initialize(ParsedUnit& u, const hilti::rt::ValueReference<T>& t, const hilti::rt::TypeInfo* ti) {
        assert(ti);

        u._unit = hilti::rt::StrongReference(t);
        u._ptr = t.get();
        u._ti = ti;
        u.tie(u._unit);
    }

private:
    hilti::rt::StrongReferenceGeneric _unit;
    const hilti::rt::TypeInfo* _ti = nullptr;
    const void* _ptr = nullptr;
};

} // namespace spicy::rt

namespace hilti::rt::detail::adl {
inline std::string to_string(const ::spicy::rt::ParsedUnit& u, adl::tag /*unused*/) { return "<parsed unit>"; };
} // namespace hilti::rt::detail::adl

namespace spicy::rt {
inline std::ostream& operator<<(std::ostream& out, const ParsedUnit& u) { return out << hilti::rt::to_string(u); }
} // namespace spicy::rt
