// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <iterator>
#include <memory>
#include <vector>

namespace hilti {

class Node;
class Operator;

class ASTRoot;
class Attribute;
class AttributeSet;
class Ctor;
class Declaration;
class Expression;
class Function;
class QualifiedType;
class Statement;
class UnqualifiedType;

namespace ctor {
class Address;
class Bool;
class Bitfield;
class Bytes;
class Coerced;
class Default;
class Enum;
class Error;
class Exception;
class Interval;
class Library;
class List;
class Map;
class Network;
class Null;
class Optional;
class Port;
class Real;
class RegExp;
class Result;
class Set;
class SignedInteger;
class Stream;
class String;
class StrongReference;
class Struct;
class Time;
class Tuple;
class Union;
class UnsignedInteger;
class ValueReference;
class Vector;
class WeakReference;
class Element;
class Field;

namespace bitfield {
class BitRange;
}

namespace map {
class Element;
}

namespace struct_ {
class Field;
}

} // namespace ctor

namespace declaration {
class Constant;
class Export;
class Expression;
class Field;
class Function;
class GlobalVariable;
class ImportedModule;
class LocalVariable;
class Module;
class Parameter;
class Property;
class Type;

} // namespace declaration

namespace expression {
class Assign;
class Coerced;
class Ctor;
class Grouping;
class Keyword;
class ListComprehension;
class LogicalAnd;
class LogicalNot;
class LogicalOr;
class Member;
class Move;
class Name;
class ConditionTest;
class PendingCoerced;
class ResolvedOperator;
class Ternary;
class TypeInfo;
class TypeWrapped;
class Type_;
class UnresolvedOperator;
class Void;
} // namespace expression

namespace operator_::generic {
class CastedCoercion;
}

namespace operator_::function {
class Call;
}

namespace operator_::struct_ {
class MemberCall;
}


namespace operator_ {

namespace address {
class Equal;
class Unequal;
class Family;
} // namespace address

namespace bitfield {
class Member;
class HasMember;
} // namespace bitfield

namespace bool_ {
class Equal;
class Unequal;
class BitAnd;
class BitOr;
class BitXor;
} // namespace bool_

namespace bytes {
namespace iterator {
class Deref;
class IncrPostfix;
class IncrPrefix;
class Equal;
class Unequal;
class Lower;
class LowerEqual;
class Greater;
class GreaterEqual;
class Difference;
class Sum;
class SumAssign;
} // namespace iterator

class Size;
class Equal;
class Unequal;
class Greater;
class GreaterEqual;
class In;
class Lower;
class LowerEqual;
class Sum;
class SumAssignBytes;
class SumAssignStreamView;
class SumAssignUInt8;
class Find;
class LowerCase;
class UpperCase;
class At;
class Split;
class Split1;
class StartsWith;
class EndsWith;
class Strip;
class SubIterators;
class SubIterator;
class SubOffsets;
class Join;
class ToIntAscii;
class ToUIntAscii;
class ToIntBinary;
class ToUIntBinary;
class ToRealAscii;
class ToTimeAscii;
class ToTimeBinary;
class Decode;
class Match;
} // namespace bytes

namespace enum_ {
class Equal;
class Unequal;
class CastToSignedInteger;
class CastToUnsignedInteger;
class CtorSigned;
class CtorUnsigned;
class HasLabel;
} // namespace enum_

namespace error {
class Ctor;
class Equal;
class Unequal;
class Description;
} // namespace error

namespace exception {
class Ctor;
class Description;
} // namespace exception

namespace generic {
class Pack;
class Unpack;
class Begin;
class End;
class New;
} // namespace generic

namespace interval {
class Equal;
class Unequal;
class Sum;
class Difference;
class Greater;
class GreaterEqual;
class Lower;
class LowerEqual;
class MultipleUnsignedInteger;
class MultipleReal;
class CtorSignedIntegerNs;
class CtorSignedIntegerSecs;
class CtorUnsignedIntegerNs;
class CtorUnsignedIntegerSecs;
class CtorRealSecs;
class Seconds;
class Nanoseconds;
} // namespace interval

namespace list {

namespace iterator {
class Deref;
class IncrPostfix;
class IncrPrefix;
class Equal;
class Unequal;
} // namespace iterator

class Size;
class Equal;
class Unequal;

} // namespace list

namespace map {

namespace iterator {
class Deref;
class IncrPostfix;
class IncrPrefix;
class Equal;
class Unequal;
} // namespace iterator

class Size;
class Equal;
class Unequal;
class In;
class Delete;
class IndexConst;
class IndexNonConst;
class IndexAssign;
class Get;
class GetOptional;
class Clear;

} // namespace map

namespace network {
class Equal;
class Unequal;
class In;
class Family;
class Prefix;
class Length;
} // namespace network

namespace optional {
class Deref;
}

namespace port {
class Equal;
class Unequal;
class Ctor;
class Protocol;
} // namespace port

namespace real {
class SignNeg;
class Difference;
class DifferenceAssign;
class Division;
class DivisionAssign;
class Equal;
class Greater;
class GreaterEqual;
class Lower;
class LowerEqual;
class Modulo;
class Multiple;
class MultipleAssign;
class Power;
class Sum;
class SumAssign;
class Unequal;
class CastToUnsignedInteger;
class CastToSignedInteger;
class CastToTime;
class CastToInterval;
} // namespace real

namespace strong_reference {
class Deref;
class Equal;
class Unequal;
} // namespace strong_reference

namespace weak_reference {
class Deref;
class Equal;
class Unequal;
} // namespace weak_reference

namespace value_reference {
class Deref;
class Equal;
class Unequal;
} // namespace value_reference

namespace regexp {
class Match;
class Find;
class MatchGroups;
class TokenMatcher;
} // namespace regexp

namespace regexp_match_state {
class AdvanceBytes;
class AdvanceView;
} // namespace regexp_match_state

namespace result {
class Deref;
class Error;
} // namespace result

namespace set {

namespace iterator {
class Deref;
class IncrPostfix;
class IncrPrefix;
class Equal;
class Unequal;
} // namespace iterator

class Size;
class Equal;
class Unequal;
class In;
class Add;
class Delete;
class Clear;

} // namespace set

namespace signed_integer {
class DecrPostfix;
class DecrPrefix;
class IncrPostfix;
class IncrPrefix;
class SignNeg;
class Difference;
class DifferenceAssign;
class Division;
class DivisionAssign;
class Equal;
class Greater;
class GreaterEqual;
class Lower;
class LowerEqual;
class Modulo;
class Multiple;
class MultipleAssign;
class Power;
class Sum;
class SumAssign;
class Unequal;
class CastToSigned;
class CastToUnsigned;
class CastToReal;
class CastToEnum;
class CastToInterval;
class CastToBool;
class CtorSigned8;
class CtorSigned16;
class CtorSigned32;
class CtorSigned64;
class CtorUnsigned8;
class CtorUnsigned16;
class CtorUnsigned32;
class CtorUnsigned64;
} // namespace signed_integer

namespace stream {

namespace iterator {
class Deref;
class IncrPostfix;
class IncrPrefix;
class Equal;
class Unequal;
class Lower;
class LowerEqual;
class Greater;
class GreaterEqual;
class Difference;
class Sum;
class SumAssign;
class Offset;
class IsFrozen;
} // namespace iterator

namespace view {
class Size;
class InBytes;
class InView;
class EqualView;
class EqualBytes;
class UnequalView;
class UnequalBytes;
class Offset;
class AdvanceBy;
class AdvanceToNextData;
class Limit;
class AdvanceTo;
class Find;
class At;
class StartsWith;
class SubIterators;
class SubIterator;
class SubOffsets;
} // namespace view

class Ctor;
class Size;
class Unequal;
class SumAssignView;
class SumAssignBytes;
class Freeze;
class Unfreeze;
class IsFrozen;
class At;
class Trim;
class Statistics;

} // namespace stream

namespace string {
class Equal;
class Unequal;
class Size;
class Sum;
class SumAssign;
class Modulo;
class Encode;
class Split;
class Split1;
class StartsWith;
class EndsWith;
class LowerCase;
class UpperCase;
} // namespace string

namespace struct_ {
class Unset;
class MemberNonConst;
class MemberConst;
class TryMember;
class HasMember;
} // namespace struct_

namespace time {
class Equal;
class Unequal;
class SumInterval;
class DifferenceTime;
class DifferenceInterval;
class Greater;
class GreaterEqual;
class Lower;
class LowerEqual;
class CtorSignedIntegerNs;
class CtorSignedIntegerSecs;
class CtorUnsignedIntegerNs;
class CtorUnsignedIntegerSecs;
class CtorRealSecs;
class Seconds;
class Nanoseconds;
} // namespace time

namespace tuple {
class Equal;
class Unequal;
class Index;
class Member;
class CustomAssign;
} // namespace tuple

namespace union_ {
class Equal;
class Unequal;
class MemberConst;
class MemberNonConst;
class HasMember;
} // namespace union_

namespace unsigned_integer {
class DecrPostfix;
class DecrPrefix;
class IncrPostfix;
class IncrPrefix;
class SignNeg;
class Difference;
class DifferenceAssign;
class Division;
class DivisionAssign;
class Equal;
class Greater;
class GreaterEqual;
class Lower;
class LowerEqual;
class Modulo;
class Multiple;
class MultipleAssign;
class Power;
class Sum;
class SumAssign;
class Unequal;
class Negate;
class BitAnd;
class BitOr;
class BitXor;
class ShiftLeft;
class ShiftRight;
class CastToUnsigned;
class CastToSigned;
class CastToReal;
class CastToEnum;
class CastToInterval;
class CastToTime;
class CastToBool;
class CtorSigned8;
class CtorSigned16;
class CtorSigned32;
class CtorSigned64;
class CtorUnsigned8;
class CtorUnsigned16;
class CtorUnsigned32;
class CtorUnsigned64;
} // namespace unsigned_integer

namespace vector {

namespace iterator {
class Deref;
class IncrPostfix;
class IncrPrefix;
class Equal;
class Unequal;
} // namespace iterator

class Size;
class Equal;
class Unequal;
class IndexConst;
class IndexNonConst;
class Sum;
class SumAssign;
class Assign;
class PushBack;
class PopBack;
class Front;
class Back;
class Reserve;
class Resize;
class At;
class SubRange;
class SubEnd;

} // namespace vector

} // namespace operator_

namespace statement {
class Assert;
class Block;
class Break;
class Comment;
class Continue;
class Declaration;
class Expression;
class For;
class If;
class Return;
class SetLocation;
class Switch;
class Throw;
class Try;
class While;
class Yield;
class Case;
class Catch;

namespace switch_ {
class Case;
}

namespace try_ {
class Catch;
}

} // namespace statement

namespace type {
class Address;
class Any;
class Auto;
class Bitfield;
class Bool;
class Bytes;
class DocOnly;
class Enum;
class Error;
class Exception;
class Function;
class Interval;
class Library;
class List;
class Map;
class Member;
class Network;
class Null;
class Name;
class OperandList;
class Optional;
class Port;
class Real;
class RegExp;
class Result;
class Set;
class SignedInteger;
class Stream;
class String;
class StrongReference;
class Struct;
class Time;
class Tuple;
class Type_;
class Union;
class Unknown;
class UnsignedInteger;
class ValueReference;
class Vector;
class Void;
class WeakReference;

namespace bitfield {
class BitRange;
}

namespace bytes {
class Iterator;
}

namespace stream {
class Iterator;
class View;
} // namespace stream

namespace list {
class Iterator;
}

namespace map {
class Iterator;
}

namespace set {
class Iterator;
}

namespace vector {
class Iterator;
}

namespace function {
using Parameter = declaration::Parameter;
} // namespace function

namespace tuple {
class Element;
}

namespace enum_ {
class Label;
}

namespace operand_list {
class Operand;
}

} // namespace type

template<typename T>
using NodeVector = std::vector<T*>;

using Attributes = NodeVector<Attribute>;
using Declarations = NodeVector<Declaration>;
using Expressions = NodeVector<Expression>;
using Statements = NodeVector<Statement>;
using QualifiedTypes = NodeVector<QualifiedType>;
using UnqualifiedTypes = NodeVector<UnqualifiedType>;

class Builder;
using BuilderPtr = std::shared_ptr<Builder>;

class ASTContext;

/**
 * Container storing a set of nodes. This is just our standard vector with an
 * additional constructor.
 */
class Nodes : public NodeVector<Node> {
public:
    using NodeVector<Node>::NodeVector;

    /** Constructor accepting a vector of pointers to a derived class. */
    template<typename T>
    Nodes(NodeVector<T> m) {
        reserve(m.size());
        for ( auto it = std::make_move_iterator(m.begin()); it != std::make_move_iterator(m.end()); ++it )
            emplace_back(*it);
    }

    Nodes() = default;
    Nodes(const Nodes&) = default;
    Nodes(Nodes&&) = default;
};

} // namespace hilti
