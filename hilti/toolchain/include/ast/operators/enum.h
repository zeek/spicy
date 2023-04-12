// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/type.h>
#include <hilti/base/logger.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_2(enum_, Equal, type::Bool(), type::constant(type::Enum(type::Wildcard())),
                    operator_::sameTypeAs(0, "enum<*>"), "Compares two enum values.");
STANDARD_OPERATOR_2(enum_, Unequal, type::Bool(), type::constant(type::Enum(type::Wildcard())),
                    operator_::sameTypeAs(0, "enum<*>"), "Compares two enum values.");
STANDARD_OPERATOR_2x(
    enum_, CastToSignedInteger, Cast, operator_::typedType(1, "int"), type::Enum(type::Wildcard()),
    type::Type_(type::SignedInteger(type::Wildcard())),
    "Casts an enum value into a signed integer. If the enum value is ``Undef``, this will return ``-1``.");
STANDARD_OPERATOR_2x(
    enum_, CastToUnsignedInteger, Cast, operator_::typedType(1, "uint"), type::Enum(type::Wildcard()),
    type::Type_(type::UnsignedInteger(type::Wildcard())),
    "Casts an enum value into a unsigned integer. This will throw an exception if the enum value is ``Undef``.");

BEGIN_CTOR(enum_, CtorSigned)
    auto ctorType() const { return type::Enum(type::Wildcard()); }

    const auto& signature() const {
        static auto _signature = Signature{.args = {{"value", type::SignedInteger(type::Wildcard())}}, .doc = R"(
Instantiates an enum instance initialized from a signed integer value. The value does
*not* need to correspond to any of the type's enumerator labels.
)"};
        return _signature;
    }
END_CTOR

BEGIN_CTOR(enum_, CtorUnsigned)
    auto ctorType() const { return type::Enum(type::Wildcard()); }

    const auto& signature() const {
        static auto _signature = Signature{.args = {{"value", type::UnsignedInteger(type::Wildcard())}}, .doc = R"(
Instantiates an enum instance initialized from an unsigned integer
value. The value does *not* need to correspond to any of the type's
enumerator labels. It must not be larger than the maximum that a
*signed* 64-bit integer value can represent.
)"};
        return _signature;
    }
END_CTOR

BEGIN_METHOD(enum_, HasLabel)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::constant(type::Enum(type::Wildcard())),
                                           .result = type::Bool(),
                                           .id = "has_label",
                                           .args = {},
                                           .doc = R"(
Returns *true* if the value of *op1* corresponds to a known enum label (other
than ``Undef``), as defined by it's type.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
