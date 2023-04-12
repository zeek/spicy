// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <vector>

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/map.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

namespace hilti::operator_ {

namespace detail {

static inline auto constantKeyType(unsigned int op, const char* doc = "<type of key>") {
    return [=](const hilti::node::Range<Expression>& /* orig_ops */,
               const hilti::node::Range<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly(doc);

        if ( op >= resolved_ops.size() ) {
            logger().internalError(
                util::fmt("keyType(): index %d out of range, only %" PRIu64 " ops available", op, resolved_ops.size()));
        }

        return type::constant(resolved_ops[op].type().as<type::Map>().keyType());
    };
}

} // namespace detail

STANDARD_OPERATOR_1(map::iterator, Deref, operator_::dereferencedType(0),
                    type::constant(type::map::Iterator(type::Wildcard())),
                    "Returns the map element that the iterator refers to.");
STANDARD_OPERATOR_1(map::iterator, IncrPostfix, operator_::sameTypeAs(0, "iterator<map<*>>"),
                    type::map::Iterator(type::Wildcard()),
                    "Advances the iterator by one map element, returning the previous position.");
STANDARD_OPERATOR_1(map::iterator, IncrPrefix, operator_::sameTypeAs(0, "iterator<map<*>>"),
                    type::map::Iterator(type::Wildcard()),
                    "Advances the iterator by one map element, returning the new position.");
STANDARD_OPERATOR_2(map::iterator, Equal, type::Bool(), type::constant(type::map::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<map<*>>"),
                    "Returns true if two map iterators refer to the same location.");
STANDARD_OPERATOR_2(map::iterator, Unequal, type::Bool(), type::constant(type::map::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<map<*>>"),
                    "Returns true if two map iterators refer to different locations.");

STANDARD_OPERATOR_1(map, Size, type::UnsignedInteger(64), type::constant(type::Map(type::Wildcard())),
                    "Returns the number of elements a map contains.");
STANDARD_OPERATOR_2(map, Equal, type::Bool(), type::constant(type::Map(type::Wildcard())),
                    operator_::sameTypeAs(0, "map<*>"), "Compares two maps element-wise.");
STANDARD_OPERATOR_2(map, Unequal, type::Bool(), type::constant(type::Map(type::Wildcard())),
                    operator_::sameTypeAs(0, "map<*>"), "Compares two maps element-wise.");
STANDARD_OPERATOR_2(map, In, type::Bool(), type::Any(), type::constant(type::Map(type::Wildcard())),
                    "Returns true if an element is part of the map.");
STANDARD_OPERATOR_2(map, Delete, type::void_, type::Map(type::Wildcard()), detail::constantKeyType(0, "key"),
                    "Removes an element from the map.")

STANDARD_OPERATOR_2x_low_prio(
    map, IndexConst, Index, operator_::constantElementType(0), type::constant(type::Map(type::Wildcard())),
    detail::constantKeyType(0, "key"),
    "Returns the map's element for the given key. The key must exist, otherwise the operation "
    "will throw a runtime error.");
STANDARD_OPERATOR_2x_lhs(map, IndexNonConst, Index, operator_::elementType(0), type::Map(type::Wildcard()),
                         detail::constantKeyType(0, "key"),
                         "Returns the map's element for the given key. The key must exist, otherwise the operation "
                         "will throw a runtime error.");

STANDARD_OPERATOR_3(map, IndexAssign, type::void_, type::Map(type::Wildcard()), detail::constantKeyType(0, "key"),
                    type::Any(),
                    "Updates the map value for a given key. If the key does not exist a new element is inserted.");

BEGIN_METHOD(map, Get)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Map(type::Wildcard()),
                                           .result = operator_::elementType(0),
                                           .id = "get",
                                           .args = {{"key", type::Any()}, {"default", type::Any(), true}},
                                           .doc = R"(
Returns the map's element for the given key. If the key does not exist, returns
the default value if provided; otherwise throws a runtime error.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(map, Clear)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::Map(type::Wildcard()), .result = type::void_, .id = "clear", .args = {}, .doc = R"(
Removes all elements from the map.
)"};
        return _signature;
    }
END_METHOD


} // namespace hilti::operator_
