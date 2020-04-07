// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/exception.h>

namespace hilti {
namespace operator_ {

BEGIN_CTOR(exception, Ctor)
    auto ctorType() const { return type::Exception(type::Wildcard()); }

    auto signature() const {
        return Signature{.args = {{.id = "msg", .type = type::String()}}, .doc = R"(
Instantiates an instance of the exception type carrying the error message *msg*.
)"};
    }
END_CTOR

BEGIN_METHOD(exception, Description)
    auto signature() const {
        return Signature{.self = type::Exception(type::Wildcard()),
                         .result = type::String(),
                         .id = "description",
                         .args = {},
                         .doc = R"(
Returns the textual message associated with an exception object.
)"};
    }
END_METHOD
} // namespace operator_
} // namespace hilti
