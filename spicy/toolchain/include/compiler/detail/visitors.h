// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <memory>
#include <utility>
#include <vector>

#include <hilti/rt/types/shared_ptr.h>

#include <hilti/ast/id.h>
#include <hilti/compiler/context.h>

namespace hilti {
class Node;
class Unit;

namespace printer {
class Stream;
}

} // namespace hilti

namespace spicy::detail::ast {

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void buildScopes(const hilti::rt::SharedPtr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool coerce(const hilti::rt::SharedPtr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
bool normalize(const hilti::rt::SharedPtr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
bool print(const hilti::Node& root, hilti::printer::Stream& out);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
bool resolve(const hilti::rt::SharedPtr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void validate_pre(const hilti::rt::SharedPtr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void validate_post(const hilti::rt::SharedPtr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

} // namespace spicy::detail::ast
