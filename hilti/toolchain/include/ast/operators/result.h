// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/result.h>

namespace hilti::operator_ {

STANDARD_OPERATOR_1(result, Deref, operator_::dereferencedType(0), type::constant(type::Result(type::Wildcard())),
                    "Retrieves value stored inside the result instance. Will throw a ``NoResult`` exception if the "
                    "result is in an error state.");

BEGIN_METHOD(result, Error)
    const auto& signature() const {
        static auto _signature =
            Signature{.self = type::Result(type::Wildcard()),
                      .result = type::Error(),
                      .id = "error",
                      .args = {},
                      .doc =
                          "Retrieves the error stored inside the result instance. Will throw a ``NoError`` "
                          "exception if the result is not in an error state."};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
