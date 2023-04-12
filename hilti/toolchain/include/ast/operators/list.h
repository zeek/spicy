// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/list.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_1(list::iterator, Deref, operator_::dereferencedType(0),
                    type::constant(type::list::Iterator(type::Wildcard())),
                    "Returns the list element that the iterator refers to.");
STANDARD_OPERATOR_1(list::iterator, IncrPostfix, operator_::sameTypeAs(0, "iterator<list<*>>"),
                    type::list::Iterator(type::Wildcard()),
                    "Advances the iterator by one list element, returning the previous position.");
STANDARD_OPERATOR_1(list::iterator, IncrPrefix, operator_::sameTypeAs(0, "iterator<list<*>>"),
                    type::list::Iterator(type::Wildcard()),
                    "Advances the iterator by one list element, returning the new position.");
STANDARD_OPERATOR_2(list::iterator, Equal, type::Bool(), type::constant(type::list::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<list<*>>"),
                    "Returns true if two lists iterators refer to the same location.");
STANDARD_OPERATOR_2(list::iterator, Unequal, type::Bool(), type::constant(type::list::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<list<*>>"),
                    "Returns true if two lists iterators refer to different locations.");

STANDARD_OPERATOR_1(list, Size, type::UnsignedInteger(64), type::constant(type::List(type::Wildcard())),
                    "Returns the number of elements a list contains.");
STANDARD_OPERATOR_2(list, Equal, type::Bool(), type::constant(type::List(type::Wildcard())),
                    operator_::sameTypeAs(0, "list<*>"), "Compares two lists element-wise.");
STANDARD_OPERATOR_2(list, Unequal, type::Bool(), type::constant(type::List(type::Wildcard())),
                    operator_::sameTypeAs(0, "list<*>"), "Compares two lists element-wise.");

} // namespace hilti::operator_
