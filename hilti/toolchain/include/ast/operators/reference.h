// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/reference.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_1(strong_reference, Deref, operator_::dereferencedType(0, "<dereferenced type>", false),
                    type::constant(type::StrongReference(type::Wildcard())),
                    "Returns the referenced instance, or throws an exception if none or expired.");
STANDARD_OPERATOR_2(strong_reference, Equal, type::Bool(), type::constant(type::StrongReference(type::Wildcard())),
                    operator_::sameTypeAs(0), "Returns true if both operands reference the same instance.")
STANDARD_OPERATOR_2(strong_reference, Unequal, type::Bool(), type::constant(type::StrongReference(type::Wildcard())),
                    operator_::sameTypeAs(0), "Returns true if the two operands reference different instances.")

STANDARD_OPERATOR_1(weak_reference, Deref, operator_::dereferencedType(0, "<dereferenced type>", false),
                    type::constant(type::WeakReference(type::Wildcard())),
                    "Returns the referenced instance, or throws an exception if none or expired.");
STANDARD_OPERATOR_2(weak_reference, Equal, type::Bool(), type::constant(type::WeakReference(type::Wildcard())),
                    operator_::sameTypeAs(0), "Returns true if both operands reference the same instance.")
STANDARD_OPERATOR_2(weak_reference, Unequal, type::Bool(), type::constant(type::WeakReference(type::Wildcard())),
                    operator_::sameTypeAs(0), "Returns true if the two operands reference different instances.")

STANDARD_OPERATOR_1(value_reference, Deref, operator_::dereferencedType(0, "<dereferenced type>", false),
                    type::constant(type::ValueReference(type::Wildcard())),
                    "Returns the referenced instance, or throws an exception if none or expired.");
STANDARD_OPERATOR_2(value_reference, Equal, type::Bool(), type::constant(type::ValueReference(type::Wildcard())),
                    operator_::sameTypeAs(0), "Returns true if the values of both operands are equal.")
STANDARD_OPERATOR_2(value_reference, Unequal, type::Bool(), type::constant(type::ValueReference(type::Wildcard())),
                    operator_::sameTypeAs(0), "Returns true if the values of both operands are not equal.")

} // namespace hilti::operator_
