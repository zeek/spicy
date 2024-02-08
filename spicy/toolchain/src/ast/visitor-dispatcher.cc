// Copyright (c) 2023 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/all.h>
#include <spicy/ast/visitor-dispatcher.h>

using namespace hilti;

SPICY_NODE_IMPLEMENTATION_0(spicy, declaration::Hook)
SPICY_NODE_IMPLEMENTATION_0(spicy, type::unit::item::switch_::Case)
SPICY_NODE_IMPLEMENTATION_1(spicy, ctor::Unit, Ctor)
SPICY_NODE_IMPLEMENTATION_1(spicy, declaration::UnitHook, Declaration)
SPICY_NODE_IMPLEMENTATION_1(spicy, operator_::unit::MemberCall, ResolvedOperator)
SPICY_NODE_IMPLEMENTATION_1(spicy, statement::Confirm, Statement)
SPICY_NODE_IMPLEMENTATION_1(spicy, statement::Print, Statement)
SPICY_NODE_IMPLEMENTATION_1(spicy, statement::Reject, Statement)
SPICY_NODE_IMPLEMENTATION_1(spicy, statement::Stop, Statement)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::Sink, UnqualifiedType)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::Unit, UnqualifiedType)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::unit::Item, hilti::Declaration)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Field, type::unit::Item)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Property, type::unit::Item)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Sink, type::unit::Item)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Switch, type::unit::Item)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::unit::item::UnitHook, type::unit::Item)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::unit::item::UnresolvedField, type::unit::Item)
SPICY_NODE_IMPLEMENTATION_1(spicy, type::unit::item::Variable, type::unit::Item)
