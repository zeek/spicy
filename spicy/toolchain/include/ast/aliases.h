// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/location.h>
#include <hilti/ast/meta.h>
#include <hilti/ast/module.h>
#include <hilti/ast/node-ref.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/statement.h>

namespace spicy {

using Attribute = hilti::Attribute;
using AttributeSet = hilti::AttributeSet;
using Ctor = hilti::Ctor;
using Declaration = hilti::Declaration;
using DocString = hilti::DocString;
using Expression = hilti::Expression;
using Function = hilti::Function;
using ID = hilti::ID;
using Location = hilti::Location;
using Meta = hilti::Meta;
using Module = hilti::Module;
using Node = hilti::Node;
using NodeRef = hilti::NodeRef;
using Operator = hilti::Operator;
using Statement = hilti::Statement;
using Type = hilti::Type;

namespace declaration {
using Linkage = hilti::declaration::Linkage;

namespace parameter {
using Kind = hilti::declaration::parameter::Kind;
} // namespace parameter

} // namespace declaration

namespace function {
using CallingConvention = hilti::function::CallingConvention;
} // namespace function

namespace type {
using namespace hilti::type;
} // namespace type

#if 0
namespace type {
using Function = hilti::type::Function;
using Void = hilti::type::Void;
using Wildcard = hilti::type::Wildcard;
using Bytes = hilti::type
}
#endif

#if 0
namespace type::function {
using Parameter = hilti::type::function::Parameter;
using Result = hilti::type::function::Result;
using Flavor = hilti::type::function::Flavor;
}
#endif

namespace node {

using None = hilti::node::None;
static const Node none = None::create();

using Properties = hilti::node::Properties;

template<typename T, typename Other>
bool isEqual(const T* this_, const Other& other) {
    return hilti::node::isEqual(this_, other);
}

} // namespace node
} // namespace spicy
