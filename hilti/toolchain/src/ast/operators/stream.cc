// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/types/bool.h>
#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/stream.h>

using namespace hilti;
using namespace hilti::operator_;

namespace {
namespace stream {

namespace iterator {

class Deref : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Deref,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Const, .type = builder->typeUnsignedInteger(64)},
            .ns = "stream::iterator",
            .doc = "Returns the character the iterator is pointing to.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::Deref)
};
HILTI_OPERATOR_IMPLEMENTATION(Deref);

class IncrPostfix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPostfix,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Mutable, .type = builder->typeStreamIterator()},
            .ns = "stream::iterator",
            .doc = "Advances the iterator by one byte, returning the previous position.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::IncrPostfix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPostfix);

class IncrPrefix : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::IncrPrefix,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Mutable, .type = builder->typeStreamIterator()},
            .ns = "stream::iterator",
            .doc = "Advances the iterator by one byte, returning the new position.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::IncrPrefix)
};
HILTI_OPERATOR_IMPLEMENTATION(IncrPrefix);

class Equal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same stream "
                "value.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::Equal)
};
HILTI_OPERATOR_IMPLEMENTATION(Equal);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same stream "
                "value.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class Lower : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Lower,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same stream "
                "value.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::Lower)
};
HILTI_OPERATOR_IMPLEMENTATION(Lower);

class LowerEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::LowerEqual,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same stream "
                "value.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::LowerEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(LowerEqual);

class Greater : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Greater,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same stream "
                "value.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::Greater)
};
HILTI_OPERATOR_IMPLEMENTATION(Greater);

class GreaterEqual : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::GreaterEqual,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::iterator",
            .doc =
                "Compares the two positions. The result is undefined if they are not referring to the same stream "
                "value.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::GreaterEqual)
};
HILTI_OPERATOR_IMPLEMENTATION(GreaterEqual);

class Difference : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Difference,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .result = {.constness = Constness::Const, .type = builder->typeSignedInteger(64)},
            .ns = "stream::iterator",
            .doc =
                "Returns the number of stream between the two iterators. The result will be negative if the second "
                "iterator points "
                "to a location before the first. The result is undefined if the iterators do not refer to the same "
                "stream "
                "instance.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::Difference)
};
HILTI_OPERATOR_IMPLEMENTATION(Difference);

class Sum : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Sum,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
            .result = {.constness = Constness::Const, .type = builder->typeStreamIterator()},
            .ns = "stream::iterator",
            .doc = "Advances the iterator by the given number of stream.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::Sum)
};
HILTI_OPERATOR_IMPLEMENTATION(Sum)

class SumAssign : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SumAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeStreamIterator()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
            .result = {.constness = Constness::Const, .type = builder->typeStreamIterator()},
            .ns = "stream::iterator",
            .doc = "Advances the iterator by the given number of stream.",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::SumAssign)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssign)

class Offset : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .member = "offset",
            .result = {.constness = Constness::Const, .type = builder->typeUnsignedInteger(64)},
            .ns = "stream::iterator",
            .doc = R"(
Returns the offset of the byte that the iterator refers to relative to the
beginning of the underlying stream value.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::Offset);
};
HILTI_OPERATOR_IMPLEMENTATION(Offset);

class IsFrozen : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
            .member = "is_frozen",
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::iterator",
            .doc = R"(
Returns whether the stream value that the iterator refers to has been frozen.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::iterator::IsFrozen);
};
HILTI_OPERATOR_IMPLEMENTATION(IsFrozen);

} // namespace iterator

namespace view {

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Size,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .result = {.constness = Constness::Const, .type = builder->typeUnsignedInteger(64)},
            .ns = "stream::view",
            .doc = "Returns the number of stream the view contains.",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class InBytes : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::In,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBytes()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::view",
            .doc = "Returns true if the right-hand-side view contains the left-hand-side bytes as a subsequence.",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::InBytes)
};
HILTI_OPERATOR_IMPLEMENTATION(InBytes);

class InView : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::In,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeBytes()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::view",
            .doc = "Returns true if the right-hand-side bytes contains the left-hand-side view as a subsequence.",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::InView)
};
HILTI_OPERATOR_IMPLEMENTATION(InView);

class EqualView : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::view",
            .doc = "Compares the views lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::EqualView)
};
HILTI_OPERATOR_IMPLEMENTATION(EqualView);

class EqualBytes : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Equal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBytes()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::view",
            .doc = "Compares a stream view and a bytes instance lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::EqualBytes)
};
HILTI_OPERATOR_IMPLEMENTATION(EqualBytes);

class UnequalView : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::view",
            .doc = "Compares two views lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::UnequalView)
};
HILTI_OPERATOR_IMPLEMENTATION(UnequalView);

class UnequalBytes : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBytes()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::view",
            .doc = "Compares a stream view and a bytes instance lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::UnequalBytes)
};
HILTI_OPERATOR_IMPLEMENTATION(UnequalBytes);

class Offset : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "offset",
            .result = {.constness = Constness::Const, .type = builder->typeUnsignedInteger(64)},
            .ns = "stream::view",
            .doc = R"(
Returns the offset of the view's starting position within the associated stream value.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::Offset);
};
HILTI_OPERATOR_IMPLEMENTATION(Offset);

class AdvanceBy : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "advance",
            .param0 =
                {
                    .name = "i",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeStreamView()},
            .ns = "stream::view",
            .doc = R"(
Advances the view's starting position to a given iterator *i*, returning the new
view. The iterator must be referring to the same stream values as the view, and
it must be equal or ahead of the view's starting position.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::AdvanceBy);
};
HILTI_OPERATOR_IMPLEMENTATION(AdvanceBy);

class AdvanceToNextData : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "advance_to_next_data",
            .result = {.constness = Constness::Const, .type = builder->typeStreamView()},
            .ns = "stream::view",
            .doc = R"(
Advances the view's starting position to the next non-gap position. This always
advances the input by at least one byte.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::AdvanceToNextData);
};
HILTI_OPERATOR_IMPLEMENTATION(AdvanceToNextData);

class Limit : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "limit",
            .param0 =
                {
                    .name = "i",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
                },
            .result = {.constness = Constness::Const, .type = builder->typeStreamView()},
            .ns = "stream::view",
            .doc = R"(
Returns a new view that keeps the current start but cuts off the end *i*
characters from that beginning. The returned view will not be able to expand any
further.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::Limit);
};
HILTI_OPERATOR_IMPLEMENTATION(Limit);

class AdvanceTo : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "advance",
            .param0 =
                {
                    .name = "i",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
                },
            .result = {.constness = Constness::Const, .type = builder->typeStreamView()},
            .ns = "stream::view",
            .doc = R"(
Advances the view's starting position by *i* stream, returning the new view.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::AdvanceTo);
};
HILTI_OPERATOR_IMPLEMENTATION(AdvanceTo);

class Find : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "find",
            .param0 =
                {
                    .name = "needle",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeBytes()},
                },
            .result = {.constness = Constness::Const,
                       .type = builder->typeTuple(
                           QualifiedTypes{builder->qualifiedType(builder->typeBool(), Constness::Const),
                                          builder->qualifiedType(builder->typeStreamIterator(), Constness::Mutable)})},
            .ns = "stream::view",
            .doc = R"(
Searches *needle* inside the view's content. Returns a tuple of a boolean and an
iterator. If *needle* was found, the boolean will be true and the iterator will point
to its first occurrence. If *needle* was not found, the boolean will be false and
the iterator will point to the last position so that everything before that is
guaranteed to not contain even a partial match of *needle* (in other words: one can
trim until that position and then restart the search from there if more data
gets appended to the underlying stream value). Note that for a simple yes/no result,
you should use the ``in`` operator instead of this method, as it's more efficient.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::Find);
};
HILTI_OPERATOR_IMPLEMENTATION(Find);

class At : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "at",
            .param0 =
                {
                    .name = "i",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
                },
            .result = {.constness = Constness::Const, .type = builder->typeStreamIterator()},
            .ns = "stream::view",
            .doc = R"(
Returns an iterator representing the offset *i* inside the view.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::At);
};
HILTI_OPERATOR_IMPLEMENTATION(At);

class StartsWith : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "starts_with",
            .param0 =
                {
                    .name = "b",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeBytes()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream::view",
            .doc = R"(
Returns true if the view starts with *b*.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::StartsWith);
};
HILTI_OPERATOR_IMPLEMENTATION(StartsWith);

class SubIterators : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "sub",
            .param0 =
                {
                    .name = "begin",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
                },
            .param1 =
                {
                    .name = "end",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeStreamView()},
            .ns = "stream::view",
            .doc = R"(
Returns a new view of the subsequence from *begin* up to (but not including)
*end*.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::SubIterators);
};
HILTI_OPERATOR_IMPLEMENTATION(SubIterators);

class SubIterator : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "sub",
            .param0 =
                {
                    .name = "end",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeStreamView()},
            .ns = "stream::view",
            .doc = R"(
Returns a new view of the subsequence from the beginning of the stream up to
(but not including) *end*.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::SubIterator);
};
HILTI_OPERATOR_IMPLEMENTATION(SubIterator);

class SubOffsets : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .member = "sub",
            .param0 =
                {
                    .name = "begin",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
                },
            .param1 =
                {
                    .name = "end",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
                },
            .result = {.constness = Constness::Const, .type = builder->typeStreamView()},
            .ns = "stream::view",
            .doc = R"(
Returns a new view of the subsequence from offset *begin* to (but not including)
offset *end*. The offsets are relative to the beginning of the view.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::view::SubOffsets);
};
HILTI_OPERATOR_IMPLEMENTATION(SubOffsets);

} // namespace view

class Ctor : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Call,
            .member = "stream",
            .param0 =
                {
                    .type = {.kind = parameter::Kind::In, .type = builder->typeBytes()},
                },
            .result = {.constness = Constness::Mutable, .type = builder->typeStream()},
            .ns = "stream",
            .doc = "Creates a stream instance pre-initialized with the given data.",
        };
    }

    HILTI_OPERATOR(hilti, stream::Ctor)
};
HILTI_OPERATOR_IMPLEMENTATION(Ctor);

class Size : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Size,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStream()},
            .result = {.constness = Constness::Const, .type = builder->typeUnsignedInteger(64)},
            .ns = "stream",
            .doc = "Returns the number of stream the value contains.",
        };
    }

    HILTI_OPERATOR(hilti, stream::Size)
};
HILTI_OPERATOR_IMPLEMENTATION(Size);

class Unequal : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::Unequal,
            .op0 = {.kind = parameter::Kind::In, .type = builder->typeStream()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStream()},
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream",
            .doc = "Compares two stream values lexicographically.",
        };
    }

    HILTI_OPERATOR(hilti, stream::Unequal)
};
HILTI_OPERATOR_IMPLEMENTATION(Unequal);

class SumAssignView : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SumAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeStream()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeStreamView()},
            .result = {.constness = Constness::Const, .type = builder->typeStream()},
            .ns = "stream",
            .doc = "Concatenates another stream's view to the target stream.",
        };
    }

    HILTI_OPERATOR(hilti, stream::SumAssignView)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssignView);

class SumAssignBytes : public Operator {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::SumAssign,
            .op0 = {.kind = parameter::Kind::InOut, .type = builder->typeStream()},
            .op1 = {.kind = parameter::Kind::In, .type = builder->typeBytes()},
            .result = {.constness = Constness::Const, .type = builder->typeStream()},
            .ns = "stream",
            .doc = "Concatenates data to the stream.",
        };
    }

    HILTI_OPERATOR(hilti, stream::SumAssignBytes)
};
HILTI_OPERATOR_IMPLEMENTATION(SumAssignBytes);

class Freeze : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::InOut, .type = builder->typeStream()},
            .member = "freeze",
            .result = {.constness = Constness::Const, .type = builder->typeVoid()},
            .ns = "stream",
            .doc = R"(
Freezes the stream value. Once frozen, one cannot append any more data to a
frozen stream value (unless it gets unfrozen first). If the value is
already frozen, the operation does not change anything.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::Freeze);
};
HILTI_OPERATOR_IMPLEMENTATION(Freeze);

class Unfreeze : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::InOut, .type = builder->typeStream()},
            .member = "unfreeze",
            .result = {.constness = Constness::Const, .type = builder->typeVoid()},
            .ns = "stream",
            .doc = R"(
Unfreezes the stream value. A unfrozen stream value can be further modified. If
the value is already unfrozen (which is the default), the operation does not
change anything.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::Unfreeze);
};
HILTI_OPERATOR_IMPLEMENTATION(Unfreeze);

class IsFrozen : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStream()},
            .member = "is_frozen",
            .result = {.constness = Constness::Const, .type = builder->typeBool()},
            .ns = "stream",
            .doc = R"(
Returns true if the stream value has been frozen.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::IsFrozen);
};
HILTI_OPERATOR_IMPLEMENTATION(IsFrozen);

class At : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStream()},
            .member = "at",
            .param0 =
                {
                    .name = "i",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeUnsignedInteger(64)},
                },
            .result = {.constness = Constness::Const, .type = builder->typeStreamIterator()},
            .ns = "stream",
            .doc = R"(
Returns an iterator representing the offset *i* inside the stream value.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::At);
};
HILTI_OPERATOR_IMPLEMENTATION(At);

class Trim : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::InOut, .type = builder->typeStream()},
            .member = "trim",
            .param0 =
                {
                    .name = "i",
                    .type = {.kind = parameter::Kind::In, .type = builder->typeStreamIterator()},
                },
            .result = {.constness = Constness::Const, .type = builder->typeVoid()},
            .ns = "stream",
            .doc = R"(
Trims the stream value by removing all data from its beginning up to (but not
including) the position *i*. The iterator *i* will remain valid afterwards and
will still point to the same location, which will now be the beginning of the stream's
value. All existing iterators pointing to *i* or beyond will remain valid and keep
their offsets as well. The effect of this operation is undefined if *i* does not
actually refer to a location inside the stream value. Trimming is permitted
even on frozen values.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::Trim);
};
HILTI_OPERATOR_IMPLEMENTATION(Trim);

class Statistics : public BuiltInMemberCall {
public:
    Signature signature(Builder* builder) const final {
        return Signature{
            .kind = Kind::MemberCall,
            .self = {.kind = parameter::Kind::In, .type = builder->typeStream()},
            .member = "statistics",
            .result = {.constness = Constness::Const, .type = builder->typeName("hilti::StreamStatistics")},
            .ns = "stream",
            .doc = R"(
Returns statistics about the stream input received so far. Note that
during parsing, this reflects all input that has already been sent to
the stream, which may include data that has not been processed yet.
)",
        };
    }

    HILTI_OPERATOR(hilti, stream::Statistics);
};
HILTI_OPERATOR_IMPLEMENTATION(Statistics);

} // namespace stream
} // namespace
