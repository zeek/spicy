// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/map.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

namespace hilti {
namespace operator_ {

namespace detail {

static inline auto constantKeyType(unsigned int op, const char* doc = "<type of key>") {
    return [=](const std::vector<Expression>& /* orig_ops */,
               const std::vector<Expression>& resolved_ops) -> std::optional<Type> {
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
                    "Returns true if two maps iterators refer to the same location.");
STANDARD_OPERATOR_2(map::iterator, Unequal, type::Bool(), type::constant(type::map::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<map<*>>"),
                    "Returns true if two maps iterators refer to different locations.");

STANDARD_OPERATOR_1(map, Size, type::UnsignedInteger(64), type::constant(type::Map(type::Wildcard())),
                    "Returns the number of elements a map contains.");
STANDARD_OPERATOR_2(map, Equal, type::Bool(), type::constant(type::Map(type::Wildcard())),
                    operator_::sameTypeAs(0, "map<*>"), "Compares two maps element-wise.");
STANDARD_OPERATOR_2(map, Unequal, type::Bool(), type::constant(type::Map(type::Wildcard())),
                    operator_::sameTypeAs(0, "map<*>"), "Compares two maps element-wise.");
STANDARD_OPERATOR_2(map, In, type::Bool(), type::Any(), type::constant(type::Map(type::Wildcard())),
                    "Returns true if an element is part of the map.");
STANDARD_OPERATOR_2(map, Delete, type::Void(), type::Map(type::Wildcard()), detail::constantKeyType(0),
                    "Removes an element from the map.")

STANDARD_OPERATOR_2x(map, IndexConst, Index, operator_::constantElementType(0),
                     type::constant(type::Map(type::Wildcard())), type::Any(),
                     "Returns the map's element for the given key.");
STANDARD_OPERATOR_2x_lhs(map, IndexNonConst, Index, operator_::elementType(0), type::Map(type::Wildcard()), type::Any(),
                         "Returns the map's element for the given key. The key must exists, otherwise the operation "
                         "will throw a runtime error.");


BEGIN_METHOD(map, Get)
    auto signature() const {
        return Signature{.self = type::Map(type::Wildcard()),
                         .result = operator_::elementType(0),
                         .id = "get",
                         .args = {{.id = "key", .type = type::Any()},
                                  {.id = "default", .type = type::Any(), .optional = true}},
                         .doc = R"(
Returns the map's element for the given key. If the key does not exist, returns
the default value if provided; otherwise throws a runtime error.
)"};
    }
END_METHOD

BEGIN_METHOD(map, Clear)
    auto signature() const {
        return Signature{.self = type::Map(type::Wildcard()),
                         .result = type::Void(),
                         .id = "clear",
                         .args = {},
                         .doc = R"(
Removes all elements from the map.
)"};
    }
END_METHOD


} // namespace operator_

} // namespace hilti
