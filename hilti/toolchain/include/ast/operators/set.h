// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/set.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_1(set::iterator, Deref, operator_::dereferencedType(0),
                    type::constant(type::set::Iterator(type::Wildcard())),
                    "Returns the set element that the iterator refers to.");
STANDARD_OPERATOR_1(set::iterator, IncrPostfix, operator_::sameTypeAs(0, "iterator<set<*>>"),
                    type::set::Iterator(type::Wildcard()),
                    "Advances the iterator by one set element, returning the previous position.");
STANDARD_OPERATOR_1(set::iterator, IncrPrefix, operator_::sameTypeAs(0, "iterator<set<*>>"),
                    type::set::Iterator(type::Wildcard()),
                    "Advances the iterator by one set element, returning the new position.");
STANDARD_OPERATOR_2(set::iterator, Equal, type::Bool(), type::constant(type::set::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<set<*>>"),
                    "Returns true if two sets iterators refer to the same location.");
STANDARD_OPERATOR_2(set::iterator, Unequal, type::Bool(), type::constant(type::set::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<set<*>>"),
                    "Returns true if two sets iterators refer to different locations.");

STANDARD_OPERATOR_1(set, Size, type::UnsignedInteger(64), type::constant(type::Set(type::Wildcard())),
                    "Returns the number of elements a set contains.");
STANDARD_OPERATOR_2(set, Equal, type::Bool(), type::constant(type::Set(type::Wildcard())),
                    operator_::sameTypeAs(0, "set<*>"), "Compares two sets element-wise.");
STANDARD_OPERATOR_2(set, Unequal, type::Bool(), type::constant(type::Set(type::Wildcard())),
                    operator_::sameTypeAs(0, "set<*>"), "Compares two sets element-wise.");
STANDARD_OPERATOR_2(set, In, type::Bool(), type::Any(), type::constant(type::Set(type::Wildcard())),
                    "Returns true if an element is part of the set.");
STANDARD_OPERATOR_2(set, Add, type::void_, type::Set(type::Wildcard()), operator_::constantElementType(0, "element"),
                    "Adds an element to the set.")
STANDARD_OPERATOR_2(set, Delete, type::void_, type::Set(type::Wildcard()), operator_::constantElementType(0, "element"),
                    "Removes an element from the set.")

BEGIN_METHOD(set, Clear)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::Set(type::Wildcard()), .result = type::void_, .id = "clear", .args = {}, .doc = R"(
Removes all elements from the set.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
