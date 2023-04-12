// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/meta.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/unresolved-id.h>

namespace hilti::builder {

Type typeByID(::hilti::ID id, Meta m = Meta());

} // namespace hilti::builder
