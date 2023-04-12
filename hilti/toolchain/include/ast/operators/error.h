// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/error.h>

namespace hilti::operator_ { // NOLINT(modernize-concat-nested-namespaces)

STANDARD_KEYWORD_CTOR(error, Ctor, "error", type::Error(), type::String(), "Creates an error with the given message.");

BEGIN_METHOD(error, Description)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Error(),
                                           .result = type::String(),
                                           .id = "description",
                                           .args = {},
                                           .doc = "Retrieves the textual description associated with the error."};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
