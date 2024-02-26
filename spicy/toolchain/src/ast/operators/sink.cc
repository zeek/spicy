// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/operator-registry.h>
#include <hilti/ast/operator.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/types/sink.h>

using namespace spicy;
using namespace hilti::operator_;

namespace {
namespace sink {

class SizeValue : public hilti::Operator {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);

        return {
            .kind = Kind::Size,
            .op0 = {hilti::parameter::Kind::In, builder.typeSink()},
            .result = {hilti::Constness::Const, builder.typeUnsignedInteger(64)},
            .ns = "sink",
            .doc = R"(
Returns the number of bytes written into the sink so far. If the sink has
filters attached, this returns the value after filtering.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::SizeValue)
};
HILTI_OPERATOR_IMPLEMENTATION(SizeValue);

class SizeReference : public hilti::Operator {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::Size,
            .op0 = {hilti::parameter::Kind::In,
                    builder.typeStrongReference(builder.qualifiedType(builder.typeSink(), hilti::Constness::Const))},
            .result = {hilti::Constness::Const, builder_->typeUnsignedInteger(64)},
            .ns = "sink",
            .doc = R"(
Returns the number of bytes written into the referenced sink so far. If the sink has
filters attached, this returns the value after filtering.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::SizeReference)
};
HILTI_OPERATOR_IMPLEMENTATION(SizeReference);

class Close : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "close",
            .param0 = {},
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Closes a sink by disconnecting all parsing units. Afterwards the sink's state
is as if it had just been created (so new units can be connected). Note that a
sink is automatically closed when the unit it is part of is done parsing. Also
note that a previously connected parsing unit can *not* be reconnected; trying
to do so will still throw a ``UnitAlreadyConnected`` exception.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::Close);
};
HILTI_OPERATOR_IMPLEMENTATION(Close);

class Connect : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "connect",
            .param0 =
                {
                    .name = "u",
                    .type = {hilti::parameter::Kind::InOut,
                             builder.typeStrongReference(
                                 builder.qualifiedType(builder.typeUnit(hilti::type::Wildcard()),
                                                       hilti::Constness::Const))},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Connects a parsing unit to a sink. All subsequent write operations to the sink will pass their
data on to this parsing unit. Each unit can only be connected to a single sink. If
the unit is already connected, a ``UnitAlreadyConnected`` exception is thrown.
However, a sink can have more than one unit connected to it.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::Connect);
};
HILTI_OPERATOR_IMPLEMENTATION(Connect);

class ConnectMIMETypeString : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "connect_mime_type",
            .param0 =
                {
                    .name = "mt",
                    .type = {hilti::parameter::Kind::In, builder.typeString()},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Connects parsing units to a sink for all parsers that support a given MIME
type. All subsequent write operations to the sink will pass their data on to
these parsing units. The MIME type may have wildcards for type or subtype, and
the method will then connect units for all matching parsers.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::ConnectMIMETypeString);
};
HILTI_OPERATOR_IMPLEMENTATION(ConnectMIMETypeString);

class ConnectMIMETypeBytes : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "connect_mime_type",
            .param0 =
                {
                    .name = "mt",
                    .type = {hilti::parameter::Kind::In, builder.typeBytes()},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Connects parsing units to a sink for all parsers that support a given MIME
type. All subsequent write operations to the sink will pass their data on to
these parsing units. The MIME type may have wildcards for type or subtype, and
the method will then connect units for all matching parsers.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::ConnectMIMETypeBytes);
};
HILTI_OPERATOR_IMPLEMENTATION(ConnectMIMETypeBytes);

class ConnectFilter : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "connect_filter",
            .param0 =
                {
                    .name = "filter",
                    .type = {hilti::parameter::Kind::InOut,
                             builder.typeStrongReference(
                                 builder.qualifiedType(builder.typeUnit(hilti::type::Wildcard()),
                                                       hilti::Constness::Const))},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Connects a filter unit to the sink that will transform its input transparently
before forwarding it for parsing to other connected units.

Multiple filters can be added to a sink, in which case they will be chained
into a pipeline and the data will be passed through them in the order they have been
added. The parsing will then be carried out on the output of the last filter in
the chain.

Filters must be added before the first data chunk is written into the sink. If
data has already been written when a filter is added, an error is triggered.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::ConnectFilter);
};
HILTI_OPERATOR_IMPLEMENTATION(ConnectFilter);

class Gap : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "gap",
            .param0 =
                {
                    .name = "seq",
                    .type = {hilti::parameter::Kind::In, builder.typeUnsignedInteger(64)},
                },
            .param1 =
                {
                    .name = "len",
                    .type = {hilti::parameter::Kind::In, builder.typeUnsignedInteger(64)},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Reports a gap in the input stream. *seq* is the sequence number of the first
byte missing, *len* is the length of the gap.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::Gap);
};
HILTI_OPERATOR_IMPLEMENTATION(Gap);

class SequenceNumber : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::In, builder.typeSink()},
            .member = "sequence_number",
            .param0 = {},
            .result = {hilti::Constness::Const, builder.typeUnsignedInteger(64)},
            .ns = "sink",
            .doc = R"(
Returns the current sequence number of the sink's input stream, which is one
beyond the index of the last byte that has been put in order and delivered so far.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::SequenceNumber);
};
HILTI_OPERATOR_IMPLEMENTATION(SequenceNumber);

class SetAutoTrim : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "set_auto_trim",
            .param0 =
                {
                    .name = "enable",
                    .type = {hilti::parameter::Kind::In, builder.typeBool()},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Enables or disables auto-trimming. If enabled (which is the default) sink input
data is trimmed automatically once in-order and processed. See ``trim()`` for
more information about trimming.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::SetAutoTrim);
};
HILTI_OPERATOR_IMPLEMENTATION(SetAutoTrim);

class SetInitialSequenceNumber : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "set_initial_sequence_number",
            .param0 =
                {
                    .name = "seq",
                    .type = {hilti::parameter::Kind::In, builder.typeUnsignedInteger(64)},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Sets the sink's initial sequence number. All sequence numbers given to other
methods are then assumed to be absolute numbers beyond that initial number. If
the initial number is not set, the sink implicitly uses zero instead.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::SetInitialSequenceNumber);
};
HILTI_OPERATOR_IMPLEMENTATION(SetInitialSequenceNumber);

class SetPolicy : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "set_policy",
            .param0 =
                {
                    .name = "policy",
                    .type = {hilti::parameter::Kind::In, builder.typeName("spicy::ReassemblerPolicy")},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Sets a sink's reassembly policy for ambiguous input. As long as data hasn't
been trimmed, a sink will detect overlapping chunks. This policy decides how to
handle ambiguous overlaps. The default (and currently only) policy is
``ReassemblerPolicy::First``, which resolves ambiguities by taking the data
from the chunk that came first.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::SetPolicy);
};
HILTI_OPERATOR_IMPLEMENTATION(SetPolicy);

class Skip : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "skip",
            .param0 =
                {
                    .name = "seq",
                    .type = {hilti::parameter::Kind::In, builder.typeUnsignedInteger(64)},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Skips ahead in the input stream. *seq* is the sequence number where to continue
parsing. If there's still data buffered before that position it will be
ignored; if auto-skip is also active, it will be immediately deleted as well.
If new data is passed in later that comes before *seq*, that will likewise be
ignored. If the input stream is currently stuck inside a gap, and *seq* lies
beyond that gap, the stream will resume processing at *seq*.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::Skip);
};
HILTI_OPERATOR_IMPLEMENTATION(Skip);

class Trim : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "trim",
            .param0 =
                {
                    .name = "seq",
                    .type = {hilti::parameter::Kind::In, builder.typeUnsignedInteger(64)},
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
            .doc = R"(
Deletes all data that's still buffered internally up to *seq*. If processing the
input stream hasn't reached *seq* yet, parsing will also skip ahead to *seq*.

Trimming the input stream releases the memory, but that means that the sink won't be
able to detect any further data mismatches.

Note that by default, auto-trimming is enabled, which means all data is trimmed
automatically once in-order and processed.
)",
        };
    }

    HILTI_OPERATOR(spicy, sink::Trim);
};
HILTI_OPERATOR_IMPLEMENTATION(Trim);

class Write : public hilti::BuiltInMemberCall {
public:
    Signature signature(hilti::Builder* builder_) const final {
        auto builder = Builder(builder_);
        return {
            .kind = Kind::MemberCall,
            .self = {hilti::parameter::Kind::InOut, builder.typeSink()},
            .member = "write",
            .param0 =
                {
                    .name = "data",
                    .type = {hilti::parameter::Kind::In, builder.typeBytes()},
                },
            .param1 =
                {
                    .name = "seq",
                    .type = {hilti::parameter::Kind::In, builder.typeUnsignedInteger(64)},
                    .optional = true,
                },
            .param2 =
                {
                    .name = "len",
                    .type = {hilti::parameter::Kind::In, builder.typeUnsignedInteger(64)},
                    .optional = true,
                },
            .result = {hilti::Constness::Const, builder.typeVoid()},
            .ns = "sink",
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

)",
        };
    }

    HILTI_OPERATOR(spicy, sink::Write);
};
HILTI_OPERATOR_IMPLEMENTATION(Write);

} // namespace sink
} // namespace
