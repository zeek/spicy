// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#pragma once

#include <vector>

#include <hilti/ast/builder/expression.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/computed.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/stream.h>

#include <spicy/ast/types/unit.h>

namespace spicy::operator_ {

BEGIN_METHOD(unit, Offset)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::UnsignedInteger(64),
                                           .id = "offset",
                                           .args = {},
                                           .doc = R"(
Returns the offset of the current location in the input stream relative to the
unit's start. If executed from inside a field hook, the offset will represent
the first byte that the field has been parsed from. If this method is called
before the unit's parsing has begun, it will throw a runtime exception. Once
parsing has started, the offset will remain available for the unit's entire
life time.

Usage of this method requires the unit to be declared with the ``%random-access``
property.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Position)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::stream::Iterator(),
                                           .id = "position",
                                           .args = {},
                                           .doc = R"(
Returns an iterator to the current position in the unit's input stream. If
executed from inside a field hook, the position will represent the first byte
that the field has been parsed from. If this method is called before the unit's
parsing has begun, it will throw a runtime exception.

Usage of this method requires the unit to be declared with the ``%random-access``
property.
)"};
    }
END_METHOD


BEGIN_METHOD(unit, Input)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::stream::Iterator(),
                                           .id = "input",
                                           .args = {},
                                           .doc = R"(
Returns an iterator referring to the input location where the current unit has
begun parsing. If this method is called before the units parsing has begun, it
will throw a runtime exception. Once available, the input position will remain
accessible for the unit's entire life time.

Usage of this method requires the unit to be declared with the ``%random-access``
property.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, SetInput)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::Void(),
                                           .id = "set_input",
                                           .args = {{.id = "i",
                                                     .type = type::constant(hilti::type::stream::Iterator())}},
                                           .doc = R"(
Moves the current parsing position to *i*. The iterator *i* must be into the
input of the current unit, or the method will throw a runtime execption.

Usage of this method requires the unit to be declared with the ``%random-access``
property.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Find)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::Optional(hilti::type::stream::Iterator()),
                                           .id = "find",
                                           .args =
                                               {
                                                   {.id = "needle", .type = type::constant(hilti::type::Bytes())},
                                                   {.id = "dir",
                                                    .type = type::constant(hilti::type::Enum(type::Wildcard())),
                                                    .optional = true},
                                                   {.id = "start",
                                                    .type = type::constant(hilti::type::stream::Iterator()),
                                                    .optional = true},

                                               },
                                           .doc = R"(
Searches a *needle* pattern inside the input region defined by where the unit
began parsing and its current parsing position. If executed from inside a field
hook, the current parasing position will represent the *first* byte that the
field has been parsed from. By default, the search will start at the beginning
of that region and scan forward. If the direction is
``spicy::Direcction::Backward``, the search will start at the end of the region
and scan backward. In either case, a starting position can also be explicitly
given, but must lie inside the same region.

Usage of this method requires the unit to be declared with the ``%random-access``
property.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, ConnectFilter)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::Void(),
                                           .id = "connect_filter",
                                           .args = {{.id = "filter",
                                                     .type = hilti::type::StrongReference(
                                                         spicy::type::Unit(type::Wildcard()))}},
                                           .doc = R"(
Connects a separate filter unit to transform the unit's input transparently
before parsing. The filter unit will see the original input, and this unit will
receive everything the filter passes on through ``forward()``.

Filters can be connected only before a unit's parsing begins. The latest
possible point is from inside the target unit's ``%init`` hook.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Forward)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::Void(),
                                           .id = "forward",
                                           .args = {{.id = "data", .type = hilti::type::Bytes()}},
                                           .doc = R"(
If the unit is connected as a filter to another one, this method forwards
transformed input over to that other one to parse. If the unit is not connected,
this method will silently discard the data.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, ForwardEod)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::Void(),
                                           .id = "forward_eod",
                                           .args = {},
                                           .doc = R"(
If the unit is connected as a filter to another one, this method signals that
other one that end of its input has been reached. If the unit is not connected,
this method will not do anything.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, Backtrack)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = hilti::type::Void(),
                                           .id = "backtrack",
                                           .args = {},
                                           .doc = R"(
Aborts parsing at the current position and returns back to the most recent
``&try`` attribute. Turns into a parse error if there's no ``&try`` in scope.
)"};
    }
END_METHOD

static inline auto contextResult(bool is_const) {
    return [=](const std::vector<Expression>& /* orig_ops */,
               const std::vector<Expression>& resolved_ops) -> std::optional<Type> {
        if ( resolved_ops.empty() )
            return type::DocOnly("<context>&");

        return type::Computed(hilti::builder::member(hilti::builder::id("self"), "__context"));
    };
}

BEGIN_METHOD(unit, ContextConst)
    auto signature() const {
        return hilti::operator_::Signature{.self = hilti::type::constant(spicy::type::Unit(type::Wildcard())),
                                           .result = contextResult(true),
                                           .id = "context",
                                           .args = {},
                                           .doc = R"(
Returns a reference to the ``%context`` instance associated with the unit.
)"};
    }
END_METHOD

BEGIN_METHOD(unit, ContextNonConst)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Unit(type::Wildcard()),
                                           .result = contextResult(false),
                                           .id = "context",
                                           .args = {},
                                           .doc = R"(
Returns a reference to the ``%context`` instance associated with the unit.
)"};
    }
END_METHOD

} // namespace spicy::operator_
