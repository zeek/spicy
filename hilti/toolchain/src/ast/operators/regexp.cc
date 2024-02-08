// Copyright (c) 2021-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/library.h>
#include <hilti/ast/types/regexp.h>
#include <hilti/ast/types/stream.h>
#include <hilti/ast/types/tuple.h>
#include <hilti/ast/types/vector.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace regexp {

class Match : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeRegExp()},
            .member = "match",
            .param0 =
                {
                    .name = "data",
                    .type = {parameter::Kind::In, builder->typeBytes()},
                },
            .result = {Const, builder->typeSignedInteger(32)},
            .ns = "regexp",
            .doc = R"(
Matches the regular expression against *data*. If it matches, returns an
integer that's greater than zero. If multiple patterns have been compiled for
parallel matching, that integer will be the ID of the matching pattern. Returns
-1 if the regular expression does not match the data, but could still yield a
match if more data were added. Returns 0 if the regular expression is not found
and adding more data wouldn't change anything. The expression is considered
anchored, as though it starts with an implicit ``^`` regexp operator, to the
beginning of the data.
)",
        };
    }

    HILTI_OPERATOR(hilti, regexp::Match);
};
HILTI_OPERATOR_IMPLEMENTATION(Match);

class Find : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeRegExp()},
            .member = "find",
            .param0 =
                {
                    .name = "data",
                    .type = {parameter::Kind::In, builder->typeBytes()},
                },
            .result = {Const, builder->typeTuple({builder->qualifiedType(builder->typeSignedInteger(32), Const),
                                                  builder->qualifiedType(builder->typeBytes(), NonConst)})},
            .ns = "regexp",
            .doc = R"(
Searches the regular expression in *data* and returns the matching part.
Different from ``match``, this does not anchor the expression to the beginning
of the data: it will find matches at arbitrary starting positions. Returns a
2-tuple with (1) an integer match indicator with the same semantics as that
returned by ``find``; and (2) if a match has been found, the data that matches
the regular expression. (Note: Currently this function has a runtime that's
quadratic in the size of *data*; consider using `match` if performance is an
issue.)
)",
        };
    }

    HILTI_OPERATOR(hilti, regexp::Find);
};
HILTI_OPERATOR_IMPLEMENTATION(Find);

class MatchGroups : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeRegExp()},
            .member = "match_groups",
            .param0 =
                {
                    .name = "data",
                    .type = {parameter::Kind::In, builder->typeBytes()},
                },
            .result = {NonConst, builder->typeVector(builder->qualifiedType(builder->typeBytes(), NonConst))},
            .ns = "regexp",
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
)",
        };
    }

    HILTI_OPERATOR(hilti, regexp::MatchGroups);
};
HILTI_OPERATOR_IMPLEMENTATION(MatchGroups);

class TokenMatcher : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeRegExp()},
            .member = "token_matcher",
            .result = {Const, builder->typeName("hilti::MatchState")},
            .ns = "regexp",
            .doc = R"(
Initializes state for matching regular expression incrementally against chunks
of future input. The expression is considered anchored, as though it starts
with an implicit ``^`` regexp operator, to the beginning of the data.
)",
        };
    }

    HILTI_OPERATOR(hilti, regexp::TokenMatcher);
};
HILTI_OPERATOR_IMPLEMENTATION(TokenMatcher);

class AdvanceBytes : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeName("hilti::MatchState")},
            .member = "advance",
            .param0 =
                {
                    .name = "data",
                    .type = {parameter::Kind::In, builder->typeBytes()},
                },
            .param1 =
                {
                    .name = "final",
                    .type = {parameter::Kind::In, builder->typeBool()},
                    .default_ = builder->expressionCtor(builder->ctorBool(false)),
                },
            .result = {Const, builder->typeTuple({builder->qualifiedType(builder->typeSignedInteger(32), Const),
                                                  builder->qualifiedType(builder->typeStreamView(), NonConst)})},
            .ns = "regexp_match_state",
            .doc = R"(
Feeds a chunk of data into the token match state, continuing matching where it
left off last time. If *final* is true, this is assumed to be the final piece
of data; any further advancing will then lead to an exception. Returns a
2-tuple with (1) an integer match indicator with the same semantics as that
returned by ``regexp::match()``; and (2) the number of bytes in *data* consumed
by the matching. The state must not be used again once an integer larger
or equal zero has been returned.
)",
        };
    }

    HILTI_OPERATOR(hilti, regexp_match_state::AdvanceBytes);
};
HILTI_OPERATOR_IMPLEMENTATION(AdvanceBytes);

class AdvanceView : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return {
            .kind = Kind::MemberCall,
            .self = {parameter::Kind::In, builder->typeName("hilti::MatchState")},
            .member = "advance",
            .param0 =
                {
                    .name = "data",
                    .type = {parameter::Kind::In, builder->typeStreamView()},
                },
            .param1 =
                {
                    .name = "final",
                    .type = {parameter::Kind::In, builder->typeBool()},
                    .default_ = builder->expressionCtor(builder->ctorBool(false)),
                },
            .result = {Const, builder->typeTuple({builder->qualifiedType(builder->typeSignedInteger(32), Const),
                                                  builder->qualifiedType(builder->typeStreamView(), NonConst)})},
            .ns = "regexp_match_state",
            .doc = R"(
Feeds a chunk of data into the token match state, continuing matching where it
left off last time. If the underlying view is frozen, this will be assumed to
be last piece of data; any further advancing will then lead to an exception.
Returns a 2-tuple with (1) an integer match indicator with the same semantics as
that returned by ``regexp::match()``; and (2) a new view that's trimming *data*
to the part not yet consumed. The state must not be used again once an integer
larger or equal zero has been returned.
)",
        };
    }

    HILTI_OPERATOR(hilti, regexp_match_state::AdvanceView);
};
HILTI_OPERATOR_IMPLEMENTATION(AdvanceView);

} // namespace regexp
} // namespace
