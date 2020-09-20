// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operator.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bytes.h>
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

Usage of this method requires the unit to be declared with the `%random-access`
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

Usage of this method requires the unit to be declared with the `%random-access`
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
Moves the current parsing position to *i*. The new position *i* must be located
inside the range between the first bytes of the current unit (i.e., the result
of ``self.input()``) and the current parsing position. If the new position is
outside of that range, the method will throw a runtime exception.

Usage of this method requires the unit to be declared with the `%random-access`
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
receive everything the filter passes on through `forward()`.

Filters can be connected only before a unit's parsing begins. The latest
possible point is from inside the target unit's `%init` hook.
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

} // namespace spicy::operator_
