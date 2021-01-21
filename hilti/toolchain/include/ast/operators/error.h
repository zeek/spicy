// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/error.h>

namespace hilti {
namespace operator_ {

BEGIN_METHOD(error, Description)
    auto signature() const {
        return Signature{.self = type::Error(),
                         .result = type::String(),
                         .id = "description",
                         .args = {},
                         .doc = "Retrieves the textual description associated with the error."};
    }
END_METHOD

} // namespace operator_
} // namespace hilti
