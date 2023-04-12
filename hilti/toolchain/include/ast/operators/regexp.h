// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

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

BEGIN_METHOD(regexp, Match)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::RegExp(),
                                           .result = type::SignedInteger(32),
                                           .id = "match",
                                           .args = {{"data", type::constant(type::Bytes())}},
                                           .doc = R"(
Matches the regular expression against *data*. If it matches, returns an
integer that's greater than zero. If multiple patterns have been compiled for
parallel matching, that integer will be the ID of the matching pattern. Returns
-1 if the regular expression does not match the data, but could still yield a
match if more data were added. Returns 0 if the regular expression is not found
and adding more data wouldn't change anything. The expression is considered
anchored, as though it starts with an implicit ``^`` regexp operator, to the
beginning of the data.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(regexp, Find)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::RegExp(),
                                           .result = type::Tuple({type::SignedInteger(32), type::Bytes()}),
                                           .id = "find",
                                           .args = {{"data", type::constant(type::Bytes())}},
                                           .doc = R"(
Searches the regular expression in *data* and returns the matching part.
Different from ``match``, this does not anchor the expression to the beginning
of the data: it will find matches at arbitrary starting positions. Returns a
2-tuple with (1) an integer match indicator with the same semantics as that
returned by ``find``; and (2) if a match has been found, the data that matches
the regular expression. (Note: Currently this function has a runtime that's
quadratic in the size of *data*; consider using `match` if performance is an
issue.)
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(regexp, MatchGroups)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::RegExp(),
                                           .result = type::Vector(type::Bytes()),
                                           .id = "match_groups",
                                           .args = {{"data", type::constant(type::Bytes())}},
                                           .doc = R"(
Matches the regular expression against *data*. If it matches, returns a vector
with one entry for each capture group defined by the regular expression;
starting at index 1. Each of these entries is a view locating the matching
bytes. In addition, index 0 always contains the data that matches the full
regular expression. Returns an empty vector if the expression is not found. The
expression is considered anchored, as though it starts with an implicit ``^``
regexp operator, to the beginning of the data. This method is not compatible
with pattern sets and will throw a runtime exception if used with a regular
expression compiled from a set.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(regexp, TokenMatcher)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::RegExp(),
                                           .result = builder::typeByID("hilti::MatchState"),
                                           .id = "token_matcher",
                                           .args = {},
                                           .doc = R"(
Initializes state for matching regular expression incrementally against chunks
of future input. The expression is considered anchored, as though it starts
with an implicit ``^`` regexp operator, to the beginning of the data.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(regexp_match_state, AdvanceBytes)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Library("hilti::rt::regexp::MatchState"),
                                           .result = type::Tuple({type::SignedInteger(32), type::stream::View()}),
                                           .id = "advance",
                                           .args = {{"data", type::constant(type::Bytes())},
                                                    {"final", type::Bool(), false, expression::Ctor(ctor::Bool(true))}},
                                           .doc = R"(
Feeds a chunk of data into the token match state, continuing matching where it
left off last time. If *final* is true, this is assumed to be the final piece
of data; any further advancing will then lead to an exception. Returns a
2-tuple with (1) an integer match indicator with the same semantics as that
returned by ``regexp::match()``; and (2) the number of bytes in *data* consumed
by the matching. The state must not be used again once an integer larger
or equal zero has been returned.
)"};
        return _signature;
    }
END_METHOD

BEGIN_METHOD(regexp_match_state, AdvanceView)
    const auto& signature() const {
        static auto _signature = Signature{.self = type::Library("hilti::rt::regexp::MatchState"),
                                           .result = type::Tuple({type::SignedInteger(32), type::stream::View()}),
                                           .id = "advance",
                                           .args = {{"data", type::constant(type::stream::View())}},
                                           .doc = R"(
Feeds a chunk of data into the token match state, continuing matching where it
left off last time. If the underlying view is frozen, this will be assumed to
be last piece of data; any further advancing will then lead to an exception.
Returns a 2-tuple with (1) an integer match indicator with the same semantics as
that returned by ``regexp::match()``; and (2) a new view that's trimming *data*
to the part not yet consumed. The state must not be used again once an integer
larger or equal zero has been returned.
)"};
        return _signature;
    }
END_METHOD

} // namespace hilti::operator_
