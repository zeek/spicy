// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/result.h>

namespace hilti {
namespace operator_ {

STANDARD_OPERATOR_1(result, Deref, operator_::dereferencedType(0), type::constant(type::Result(type::Wildcard())),
                    "Retrieves value stored inside the result instance. Will throw a ``NoResult`` exception if the "
                    "result is in an error state.");

BEGIN_METHOD(result, Error)
    auto signature() const {
        return Signature{.self = type::Result(type::Wildcard()),
                         .result = type::Error(),
                         .id = "error",
                         .args = {},
                         .doc =
                             "Retrieves the error stored inside the result instance. Will throw a ``NoError`` "
                             "exception if the result is not in an error state."};
    }
END_METHOD

} // namespace operator_
} // namespace hilti
