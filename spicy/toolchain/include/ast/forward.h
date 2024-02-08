// Copyright (c) 2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <memory>
#include <vector>

#include <hilti/ast/forward.h>

namespace hilti::node {}

namespace hilti {
class ID;
class Meta;
class Location;

template<typename Builder>
class ExtendedBuilderTemplate;

} // namespace hilti

namespace spicy {

namespace node = hilti::node; // NOLINT

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

using HookPtr = std::shared_ptr<Hook>;
using Hooks = std::vector<HookPtr>;
} // namespace declaration

#include <spicy/autogen/__ast-forward.h>

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
using ItemPtr = std::shared_ptr<Item>;
using Items = std::vector<ItemPtr>;

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
using CasePtr = std::shared_ptr<Case>;
using Cases = std::vector<CasePtr>;
}; // namespace switch_

using HookPtr = std::shared_ptr<declaration::Hook>;
using FieldPtr = std::shared_ptr<Field>;
using ItemPtr = std::shared_ptr<Item>;
using PropertyPtr = std::shared_ptr<Property>;
using SinkPtr = std::shared_ptr<Sink>;
using VariablePtr = std::shared_ptr<Variable>;
using SwitchPtr = std::shared_ptr<Switch>;
using UnitHookPtr = std::shared_ptr<UnitHook>;
using UnresolvedFieldPtr = std::shared_ptr<UnresolvedField>;

using Properties = std::vector<PropertyPtr>;
} // namespace item

} // namespace unit

using UnitPtr = std::shared_ptr<Unit>;

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

using AttributePtr = hilti::AttributePtr;
using AttributeSetPtr = hilti::AttributeSetPtr;
using CtorPtr = hilti::CtorPtr;
using DeclarationPtr = hilti::DeclarationPtr;
using ExpressionPtr = hilti::ExpressionPtr;
using FunctionPtr = hilti::FunctionPtr;
using NodePtr = hilti::NodePtr;
using StatementPtr = hilti::StatementPtr;
using QualifiedTypePtr = hilti::QualifiedTypePtr;
using UnqualifiedTypePtr = hilti::UnqualifiedTypePtr;
using ModulePtr = hilti::ModulePtr;
using ASTRootPtr = hilti::ASTRootPtr;

using Nodes = hilti::Nodes;
using Expressions = hilti::Expressions;
using Statements = hilti::Statements;
using Declarations = hilti::Declarations;

using ASTContext = hilti::ASTContext;
using Meta = hilti::Meta;
using Location = hilti::Location;

} // namespace spicy
