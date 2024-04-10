// Copyright (c) 2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <vector>

#include <hilti/ast/forward.h>

#include <spicy/ast/node-tag.h>

namespace hilti {
class ID;
class Meta;
class Location;

template<typename Builder>
class ExtendedBuilderTemplate;

} // namespace hilti

namespace spicy {

namespace node = hilti::node; // NOLINT

template<typename T>
using NodeVector = hilti::NodeVector<T>;

using Node = hilti::Node;
using Nodes = hilti::Nodes;

class BuilderBase;
using Builder = hilti::ExtendedBuilderTemplate<BuilderBase>;
using BuilderPtr = std::shared_ptr<Builder>;

namespace builder {
class NodeBuilder;
} // namespace builder

namespace ctor {
class Unit;
}

namespace declaration {
class Hook;
class UnitHook;

using Hooks = NodeVector<Hook>;
} // namespace declaration

namespace operator_ {

namespace sink {
class Size;
class Close;
class Connect;
class ConnectMIMETypeString;
class ConnectMIMETypeBytes;
class ConnectFilter;
class Gap;
class SequenceNumber;
class SetAutoTrim;
class SetInitialSequenceNumber;
class SetPolicy;
class Skip;
class Trim;
class Write;
} // namespace sink

namespace unit {
class Unset;
class MemberNonConst;
class MemberConst;
class TryMember;
class HasMember;
class Offset;
class Position;
class Input;
class SetInput;
class Find;
class ConnectFilter;
class Forward;
class ForwardEod;
class Backtrack;
class ContextConst;
class ContextNonConst;
} // namespace unit

} // namespace operator_

namespace operator_::unit {
class MemberCall;
}

namespace statement {
class Confirm;
class Print;
class Reject;
class Stop;
} // namespace statement

namespace type {
class Sink;
class Unit;

namespace unit {
class Item;
using Items = NodeVector<Item>;

namespace item {
class Field;
class Property;
class Sink;
class Switch;
class UnitHook;
class UnresolvedField;
class Variable;

namespace switch_ {
class Case;
using Cases = NodeVector<Case>;
}; // namespace switch_

using Properties = NodeVector<Property>;
} // namespace item

} // namespace unit

} // namespace type

// Import some HILTI types for convenience.
using Ctor = hilti::Ctor;
using Declaration = hilti::Declaration;
using Expression = hilti::Expression;
using Function = hilti::Function;
using ID = hilti::ID;
using Location = hilti::Location;
using Meta = hilti::Meta;
using Node = hilti::Node;
using QualifiedType = hilti::QualifiedType;
using Statement = hilti::Statement;
using UnqualifiedType = hilti::UnqualifiedType;
using AttributeSet = hilti::AttributeSet;

using Declarations = hilti::Declarations;
using Expressions = hilti::Expressions;
using QualifiedTypes = hilti::QualifiedTypes;
using Statements = hilti::Statements;

using ASTContext = hilti::ASTContext;
using Meta = hilti::Meta;
using Location = hilti::Location;

} // namespace spicy
