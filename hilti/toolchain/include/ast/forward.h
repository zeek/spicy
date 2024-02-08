// Copyright (c) 2023 by the Zeek Project. See LICENSE for details.

#pragma once

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

using ParameterPtr = std::shared_ptr<Parameter>;

} // namespace declaration

namespace expression {
class Assign;
class BuiltInFunction;
class Coerced;
class Ctor;
class Deferred;
class Grouping;
class Keyword;
class ListComprehension;
class LogicalAnd;
class LogicalNot;
class LogicalOr;
class Member;
class Move;
class Name;
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

#include <hilti/autogen/__ast-forward.h>

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
using ParameterPtr = declaration::ParameterPtr;
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

using ASTRootPtr = std::shared_ptr<ASTRoot>;
using AttributePtr = std::shared_ptr<Attribute>;
using AttributeSetPtr = std::shared_ptr<AttributeSet>;
using CtorPtr = std::shared_ptr<Ctor>;
using DeclarationPtr = std::shared_ptr<Declaration>;
using ExpressionPtr = std::shared_ptr<Expression>;
using FunctionPtr = std::shared_ptr<Function>;
using ModulePtr = std::shared_ptr<declaration::Module>;
using NodePtr = std::shared_ptr<Node>;
using StatementPtr = std::shared_ptr<Statement>;
using UnqualifiedTypePtr = std::shared_ptr<UnqualifiedType>;
using QualifiedTypePtr = std::shared_ptr<QualifiedType>;
using ResolvedOperatorPtr = std::shared_ptr<expression::ResolvedOperator>;
using UnresolvedOperatorPtr = std::shared_ptr<expression::UnresolvedOperator>;
using OperandListPtr = std::shared_ptr<type::OperandList>;
using OperandPtr = std::shared_ptr<type::operand_list::Operand>;

using Attributes = std::vector<AttributePtr>;
using Declarations = std::vector<DeclarationPtr>;
using Expressions = std::vector<ExpressionPtr>;
using Statements = std::vector<StatementPtr>;
using QualifiedTypes = std::vector<QualifiedTypePtr>;
using UnqualifiedTypes = std::vector<UnqualifiedTypePtr>;

class Builder;
using BuilderPtr = std::shared_ptr<Builder>;

class ASTContext;
class Nodes;


} // namespace hilti
