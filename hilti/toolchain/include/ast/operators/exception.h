// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/exception.h>

namespace hilti::operator_ {

BEGIN_CTOR(exception, Ctor)
    auto ctorType() const { return type::Exception(type::Wildcard()); }

    const auto& signature() const {
        static auto _signature = Signature{.args = {{"msg", type::String()}}, .doc = R"(
Instantiates an instance of the exception type carrying the error message *msg*.
)"};
        return _signature;
    }
END_CTOR

BEGIN_METHOD(exception, Description)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Exception(type::Wildcard()),
                                           .result = type::String(),
                                           .id = "description",
                                           .args = {},
                                           .doc = R"(
Returns the textual message associated with an exception object.
)"};
        return _signature;
    }
END_METHOD
} // namespace hilti::operator_
