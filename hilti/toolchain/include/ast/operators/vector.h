// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/vector.h>
#include <hilti/ast/types/void.h>
#include <hilti/base/util.h>

namespace hilti {
namespace operator_ {

STANDARD_OPERATOR_1(vector::iterator, Deref, operator_::dereferencedType(0),
                    type::constant(type::vector::Iterator(type::Wildcard())),
                    "Returns the vector element that the iterator refers to.");
STANDARD_OPERATOR_1(vector::iterator, IncrPostfix, operator_::sameTypeAs(0, "iterator<vector<*>>"),
                    type::vector::Iterator(type::Wildcard()),
                    "Advances the iterator by one vector element, returning the previous position.");
STANDARD_OPERATOR_1(vector::iterator, IncrPrefix, operator_::sameTypeAs(0, "iterator<vector<*>>"),
                    type::vector::Iterator(type::Wildcard()),
                    "Advances the iterator by one vector element, returning the new position.");
STANDARD_OPERATOR_2(vector::iterator, Equal, type::Bool(), type::constant(type::vector::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<vector<*>>"),
                    "Returns true if two vector iterators refer to the same location.");
STANDARD_OPERATOR_2(vector::iterator, Unequal, type::Bool(), type::constant(type::vector::Iterator(type::Wildcard())),
                    operator_::sameTypeAs(0, "iterator<vector<*>>"),
                    "Returns true if two vector iterators refer to different locations.");

STANDARD_OPERATOR_1(vector, Size, type::UnsignedInteger(64), type::constant(type::Vector(type::Wildcard())),
                    "Returns the number of elements a vector contains.");
STANDARD_OPERATOR_2(vector, Equal, type::Bool(), type::constant(type::Vector(type::Wildcard())),
                    operator_::sameTypeAs(0, "vector<*>"), "Compares two vectors element-wise.");
STANDARD_OPERATOR_2x(vector, IndexConst, Index, operator_::constantElementType(0),
                     type::constant(type::Vector(type::Wildcard())), type::UnsignedInteger(64),
                     "Returns the vector element at the given index.");
STANDARD_OPERATOR_2x_lhs(vector, IndexNonConst, Index, operator_::elementType(0), type::Vector(type::Wildcard()),
                         type::UnsignedInteger(64), "Returns the vector element at the given index.");
STANDARD_OPERATOR_2(vector, Unequal, type::Bool(), type::constant(type::Vector(type::Wildcard())),
                    operator_::sameTypeAs(0, "vector<*>"), "Compares two vectors element-wise.");

STANDARD_OPERATOR_2(vector, Sum, operator_::sameTypeAs(0, "vector<*>"), type::Vector(type::Wildcard()),
                    operator_::sameTypeAs(0, "vector<*>"), "Returns the concatenation of two vectors.")
STANDARD_OPERATOR_2(vector, SumAssign, operator_::sameTypeAs(0, "vector<*>"), type::Vector(type::Wildcard()),
                    operator_::sameTypeAs(0, "vector<*>"), "Concatenates another vector to the vector.")

BEGIN_METHOD(vector, Assign)
    auto signature() const {
        return Signature{.self = type::Vector(type::Wildcard()),
                         .result = type::Void(),
                         .id = "assign",
                         .args = {{.id = "i", .type = type::UnsignedInteger(64)}, {.id = "x", .type = type::Any()}},
                         .doc = R"(
Assigns *x* to the *i*th element of the vector. If the vector contains less
than *i* elements a sufficient number of default-initialized elements is added
to carry out the assignment.
)"};
    }
END_METHOD

BEGIN_METHOD(vector, PushBack)
    auto signature() const {
        return Signature{.self = type::Vector(type::Wildcard()),
                         .result = type::Void(),
                         .id = "push_back",
                         .args = {{.id = "x", .type = type::Any()}},
                         .doc = R"(
Appends *x* to the end of the vector.
)"};
    }
END_METHOD

BEGIN_METHOD(vector, PopBack)
    auto signature() const {
        return Signature{.self = type::Vector(type::Wildcard()),
                         .result = type::Void(),
                         .id = "pop_back",
                         .args = {},
                         .doc = R"(
Removes the last element from the vector, which must be non-empty.
)"};
    }
END_METHOD

BEGIN_METHOD(vector, Front)
    auto signature() const {
        return Signature{.self = type::constant(type::Vector(type::Wildcard())),
                         .result = operator_::constantElementType(0),
                         .id = "front",
                         .args = {},
                         .doc = R"(
Returns the first element of the vector. It throws an exception if the vector is
empty.
)"};
    }
END_METHOD


BEGIN_METHOD(vector, Back)
    auto signature() const {
        return Signature{.self = type::constant(type::Vector(type::Wildcard())),
                         .result = operator_::constantElementType(0),
                         .id = "back",
                         .args = {},
                         .doc = R"(
Returns the last element of the vector. It throws an exception if the vector is
empty.
)"};
    }
END_METHOD

BEGIN_METHOD(vector, Reserve)
    auto signature() const {
        return Signature{.self = type::Vector(type::Wildcard()),
                         .result = type::Void(),
                         .id = "reserve",
                         .args = {{.id = "n", .type = type::constant(type::UnsignedInteger(64))}},
                         .doc = R"(
Reserves space for at least *n* elements. This operation does not change the
vector in any observable way but provides a hint about the size that will be
needed.
)"};
    }
END_METHOD

BEGIN_METHOD(vector, Resize)
    auto signature() const {
        return Signature{.self = type::Vector(type::Wildcard()),
                         .result = type::Void(),
                         .id = "resize",
                         .args = {{.id = "n", .type = type::constant(type::UnsignedInteger(64))}},
                         .doc = R"(
Resizes the vector to hold exactly *n* elements. If *n* is larger than the
current size, the new slots are filled with default values. If *n* is smaller
than the current size, the excessive elements are removed.
)"};
    }
END_METHOD

BEGIN_METHOD(vector, At)
    auto signature() const {
        return Signature{.self = type::constant(type::Vector(type::Wildcard())),
                         .result = operator_::iteratorType(0, true),
                         .id = "at",
                         .args = {{.id = "i", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Returns an iterator referring to the element at vector index *i*.
)"};
    }
END_METHOD

BEGIN_METHOD(vector, SubRange)
    auto signature() const {
        return Signature{.self = type::constant(type::Vector(type::Wildcard())),
                         .result = operator_::sameTypeAs(0, "vector<*>"),
                         .id = "sub",
                         .args = {{.id = "begin", .type = type::UnsignedInteger(64)},
                                  {.id = "end", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Extracts a subsequence of vector elements spanning from index *begin*
to (but not including) index *end*.
)"};
    }
END_METHOD

BEGIN_METHOD(vector, SubEnd)
    auto signature() const {
        return Signature{.self = type::constant(type::Vector(type::Wildcard())),
                         .result = operator_::sameTypeAs(0, "vector<*>"),
                         .id = "sub",
                         .args = {{.id = "end", .type = type::UnsignedInteger(64)}},
                         .doc = R"(
Extracts a subsequence of vector elements spanning from the beginning
to (but not including) the index *end* as a new vector.
)"};
    }
END_METHOD

} // namespace operator_

} // namespace hilti
