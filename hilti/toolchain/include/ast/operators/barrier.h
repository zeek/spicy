// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/barrier.h>
#include <hilti/ast/types/void.h>

namespace hilti::operator_ {

STANDARD_KEYWORD_CTOR(barrier, Ctor, "barrier", type::Barrier(type::Wildcard()),
                      type::UnsignedInteger(type::Wildcard()),
                      "Creates a barrier that will wait for the given number of parties.");

BEGIN_METHOD(barrier, Wait)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Barrier(type::Wildcard()),
                                           .result = type::void_,
                                           .id = "wait",
                                           .args = {},
                                           .doc = R"(
Blocks the caller until the barrier is released by the expected number of
parties arriving. If the barrier is already released, it will return
immediately. If the barrier gets aborted before or during the wait, the method
will throw a ``BarrierAborted`` exception.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(barrier, Arrive)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Barrier(type::Wildcard()),
                                           .result = type::void_,
                                           .id = "arrive",
                                           .args = {},
                                           .doc = R"(
Signals a party's arrival at the barrier, potentially releasing it if
the expected number of parties have been seen now. This has no effect if
the barrier is already released or aborted.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(barrier, ArriveAndWait)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Barrier(type::Wildcard()),
                                           .result = type::void_,
                                           .id = "arrive_and_wait",
                                           .args = {},
                                           .doc = R"(
Convenience method combining a `arrive()` with an immediately following
`wait()`.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(barrier, Abort)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Barrier(type::Wildcard()),
                                           .result = type::void_,
                                           .id = "abort",
                                           .args = {},
                                           .doc = R"(
Aborts the barrier, causing any waiting parties to throw a
``BarrierAborted`` exception. This has no effect if the barrier is
already released or aborted.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
