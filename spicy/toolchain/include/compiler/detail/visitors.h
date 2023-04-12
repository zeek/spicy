// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <memory>
#include <utility>
#include <vector>

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
void buildScopes(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the default HILTI compiler plugin. */
bool coerce(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
bool normalize(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
bool print(const hilti::Node& root, hilti::printer::Stream& out);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
bool resolve(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void validate_pre(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

/** Implements the corresponding functionality for the Spicy compiler plugin. */
void validate_post(const std::shared_ptr<hilti::Context>& ctx, hilti::Node* root, hilti::Unit* unit);

} // namespace spicy::detail::ast
