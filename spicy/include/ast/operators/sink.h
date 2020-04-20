// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/operator.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/enum.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/void.h>
#include <spicy/ast/types/sink.h>
#include <spicy/ast/types/unit.h>

namespace spicy::operator_ {

STANDARD_OPERATOR_1x(sink, SizeValue, Size, type::UnsignedInteger(64), type::constant(type::Sink()), R"(
Returns the number of bytes written into the sink so far. If the sink has
filters attached, this returns the value after filtering.
)");

STANDARD_OPERATOR_1x(sink, SizeReference, Size, type::UnsignedInteger(64), hilti::type::StrongReference(type::Sink()),
                     R"(
Returns the number of bytes written into the referenced sink so far. If the sink has
filters attached, this returns the value after filtering.
)");

BEGIN_METHOD(sink, Close)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "close",
                                           .args = {},
                                           .doc = R"(
Closes a sink by disconnecting all parsing units. Afterwards the sink's state
is as if it had just been created (so new units can be connected). Note that a
sink it automatically closed when the unit it is part of is done parsing. Also
note that a previously connected parsing unit can *not* be reconnected; trying
to do so will still thrown a ``UnitAlreadyConnected`` exception.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, Connect)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "connect",
                                           .args = {{.id = "u",
                                                     .type = type::StrongReference(type::Unit(type::Wildcard()))}},
                                           .doc = R"(
Connects a parsing unit to a sink. All subsequent write operations to the sink will pass their
data on to this parsing unit. Each unit can only be connected to a single sink. If
the unit is already connected, a ``UnitAlreadyConnected`` exception is thrown.
However, a sink can have more than one unit connected to it.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, ConnectMIMETypeString)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "connect_mime_type",
                                           .args = {{.id = "mt", .type = type::String()}},
                                           .doc = R"(
Connects parsing units to a sink for all parsers that support a given MIME
type. All subsequent write operations to the sink will pass their data on to
these parsing units. The MIME type may have wildcards for type or subtype, and
the method will then connect units for all matching parsers.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, ConnectMIMETypeBytes)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "connect_mime_type",
                                           .args = {{.id = "mt", .type = type::Bytes()}},
                                           .doc = R"(
Connects parsing units to a sink for all parsers that support a given MIME
type. All subsequent write operations to the sink will pass their data on to
these parsing units. The MIME type may have wildcards for type or subtype, and
the method will then connect units for all matching parsers.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, ConnectFilter)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = hilti::type::Void(),
                                           .id = "connect_filter",
                                           .args = {{.id = "filter",
                                                     .type = hilti::type::StrongReference(
                                                         spicy::type::Unit(type::Wildcard()))}},
                                           .doc = R"(
Connects a filter unit to the sink that will transform its input transparently
before forwarding it for parsing to other connected units.

Multiple filters can be added to a sink, in which case they will be chained
into a pipeline and the data will be passed through them in the order they have been
added. The parsing will then be carried out on the output of the last filter in
the chain.

Filters must be added before the first data chunk is written into the sink. If
data has already been written when a filter is added, an error is triggered.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, Gap)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "gap",
                                           .args = {{.id = "seq", .type = type::UnsignedInteger(64)},
                                                    {.id = "len", .type = type::UnsignedInteger(64)}},
                                           .doc = R"(
Reports a gap in the input stream. *seq* is the sequence number of the first
byte missing, *len* is the length of the gap.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, SequenceNumber)
    auto signature() const {
        return hilti::operator_::Signature{.self = type::constant(spicy::type::Sink()),
                                           .result = type::UnsignedInteger(64),
                                           .id = "sequence_number",
                                           .args = {},
                                           .doc = R"(
Returns the current sequence number of the sink's input stream, which is one
beyond the index of the last byte that has been put in order and delivered so far.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, SetAutoTrim)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "set_auto_trim",
                                           .args = {{.id = "enable", .type = type::Bool()}},
                                           .doc = R"(
Enables or disables auto-trimming. If enabled (which is the default) sink input
data is trimmed automatically once in-order and processed. See ``trim()`` for
more information about trimming.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, SetInitialSequenceNumber)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "set_initial_sequence_number",
                                           .args =
                                               {
                                                   {.id = "seq", .type = type::UnsignedInteger(64)},
                                               },
                                           .doc = R"(
Sets the sink's initial sequence number. All sequence numbers given to other
methods are then assumed to be absolute numbers beyond that initial number. If
the initial number is not set, the sink implicitly uses zero instead.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, SetPolicy)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "set_policy",
                                           .args =
                                               {
                                                   {.id = "policy",
                                                    .type =
                                                        type::Enum(type::Wildcard())}, // TODO(robin): Specify full type
                                               },
                                           .doc = R"(
Sets a sink's reassembly policy for ambiguous input. As long as data hasn't
been trimmed, a sink detects overlapping chunks. The policy decides how to
handle ambiguous overlaps. The default (and currently only) policy is
``ReassemblerPolicy::First``, which resolved ambiguities by taking the data
from the chunk that came first.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, Skip)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "skip",
                                           .args =
                                               {
                                                   {.id = "seq", .type = type::UnsignedInteger(64)},
                                               },
                                           .doc = R"(
Skips ahead in the input stream. *seq* is the sequence number where to continue
parsing. If there's still data buffered before that position it will be
ignored; if auto-skip is also active, it will be immediately deleted as well.
If new data is passed in later that comes before *seq*, that will likewise be
ignored. If the input stream is currently stuck inside a gap, and *seq* lies
beyond that gap, the stream will resume processing at *seq*.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, Trim)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "trim",
                                           .args =
                                               {
                                                   {.id = "seq", .type = type::UnsignedInteger(64)},
                                               },
                                           .doc = R"(
Deletes all data that's still buffered internally up to *seq*. If processing the
input stream hasn't reached *seq* yet, parsing will also skip ahead to *seq*.

Trimming the input stream releases the memory, but that means that the sink won't be
able to detect any further data mismatches.

Note that by default, auto-trimming is enabled, which means all data is trimmed
automatically once in-order and processed.
)"};
    }
END_METHOD

BEGIN_METHOD(sink, Write)
    auto signature() const {
        return hilti::operator_::Signature{.self = spicy::type::Sink(),
                                           .result = type::Void(),
                                           .id = "write",
                                           .args = {{.id = "data", .type = type::Bytes()},
                                                    {.id = "seq", .type = type::UnsignedInteger(64), .optional = true},
                                                    {.id = "len", .type = type::UnsignedInteger(64), .optional = true}},
                                           .doc = R"(
Passes data on to all connected parsing units. Multiple *write* calls act like
passing input in incrementally: The units will parse the pieces as if they were
a single stream of data. If no sequence number *seq* is provided, the data is
assumed to represent a chunk to be appended to the current end of the input
stream. If a sequence number is provided, out-of-order data will be buffered
and reassembled before being passed on. If *len* is provided, the data is assumed
to represent that many bytes inside the sequence space; if not provided, *len*
defaults to the length of *data*.

If no units are connected, the call does not have any effect. If multiple units are
connected and one parsing unit throws an exception, parsing of subsequent units
does not proceed. Note that the order in which the data is parsed to each unit
is undefined.

.. todo:: The error semantics for multiple units aren't great.

)"};
    }
END_METHOD

} // namespace spicy::operator_
