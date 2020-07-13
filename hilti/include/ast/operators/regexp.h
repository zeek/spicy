// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/operators/common.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/regexp.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/vector.h>

namespace hilti::operator_ {

BEGIN_METHOD(regexp, Find)
    auto signature() const {
        return Signature{.self = type::RegExp(),
                         .result = type::SignedInteger(32),
                         .id = "find",
                         .args = {{.id = "data", .type = type::constant(type::Bytes())}},
                         .doc = R"(
Searches the regular expression in *data*. If found, returns an integer that's greater
than zero. If multiple patterns have been compiled for parallel matching, that
integer will be the ID of the matching pattern. Returns -1 if the regular
expression is not found, but could still match if more data were added to the
input. Returns 0 if the regular expression is not found and adding more data
wouldn't change anything.
)"};
    }
END_METHOD

BEGIN_METHOD(regexp, FindSpan)
    auto signature() const {
        return Signature{.self = type::RegExp(),
                         .result = type::Tuple({type::SignedInteger(32), type::Bytes()}),
                         .id = "find_span",
                         .args = {{.id = "data", .type = type::constant(type::Bytes())}},
                         .doc = R"(
Searches the regular expression in *data*. Returns a 2-tuple with (1) a integer
match indicator with the same semantics as that returned by ``find``; and (2) if a
match has been found, the data that matches the regular expression.
)"};
    }
END_METHOD

BEGIN_METHOD(regexp, FindGroups)
    auto signature() const {
        return Signature{.self = type::RegExp(),
                         .result = type::Vector(type::Bytes()),
                         .id = "find_groups",
                         .args = {{.id = "data", .type = type::constant(type::Bytes())}},
                         .doc = R"(
Searches the regular expression in *data*. If the regular expression is found,
returns a vector with one entry for each capture group defined by the regular
expression; starting at index 1. Each of these entries is a view locating the
matching bytes. In addition, index 0 always contains the data that matches
the full regular expression. Returns an empty vector if the expression is not
found. This method is not compatible with pattern sets and will throw a runtime
exception if used with a regular expression compiled from a set.
)"};
    }
END_METHOD

BEGIN_METHOD(regexp, TokenMatcher)
    auto signature() const {
        return Signature{.self = type::RegExp(),
                         .result = type::Library("hilti::rt::regexp::MatchState"),
                         .id = "token_matcher",
                         .args = {},
                         .doc = R"(
Initializes state for matching regular expression incrementally against chunks
of future input. The regular expression will be considered implicitly anchored.
The regular expression must have been compiled with the ``&nosub`` attribute.
)"};
    }
END_METHOD

BEGIN_METHOD(regexp_match_state, AdvanceBytes)
    auto signature() const {
        return Signature{.self = type::Library("hilti::rt::regexp::MatchState"),
                         .result = type::Tuple({type::SignedInteger(32), type::stream::View()}),
                         .id = "advance",
                         .args = {{.id = "data", .type = type::constant(type::Bytes())},
                                  {.id = "final",
                                   .type = type::Bool(),
                                   .default_ = expression::Ctor(ctor::Bool(true))}},
                         .doc = R"(
Feeds a chunk of data into the token match state, continuing matching where it
left off last time. If *final* is true, this is assumed to be the final piece
of data; any further advancing will then lead to an exception. Returns a
2-tuple with (1) a integer match indicator with the same semantics as that
returned by ``regexp::find()``; and (2) the number of bytes in *data* consumed
by the matching. The state must not be used again once an integer larger
or equal zero has been returned.
)"};
    }
END_METHOD

BEGIN_METHOD(regexp_match_state, AdvanceView)
    auto signature() const {
        return Signature{.self = type::Library("hilti::rt::regexp::MatchState"),
                         .result = type::Tuple({type::SignedInteger(32), type::stream::View()}),
                         .id = "advance",
                         .args = {{.id = "data", .type = type::constant(type::stream::View())}},
                         .doc = R"(
Feeds a chunk of data into the token match state, continuing matching where it
left off last time. If the underlying view is frozen, this will be assumed to
be last piece of data; any further advancing will then lead to an exception.
Returns a 2-tuple with (1) a integer match indicator with the same semantics as
that returned by ``regexp::find()``; and (2) a new view that's triming *data*
to the part not yet consumed. The state must not be used again once an integer
larger or equal zero has been returned.
)"};
    }
END_METHOD

} // namespace hilti::operator_
