// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/types/id.h>

namespace hilti::builder {

inline Type typeByID(::hilti::ID id, Meta m = Meta()) { return hilti::type::UnresolvedID(std::move(id), std::move(m)); }

} // namespace hilti::builder
