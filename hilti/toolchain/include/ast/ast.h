// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctor.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/function.h>
#include <hilti/ast/id.h>
#include <hilti/ast/module.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/scope.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/type.h>

namespace hilti {

/** Forwards node construction to a suitable type `T`. */
template<typename T, typename... Params>
static Node to_node(Params&&... params) {
    // Must come after all other includes so that all the to_node() are available.
    return to_node(T(std::forward<Params>(params)...));
}
} // namespace hilti
