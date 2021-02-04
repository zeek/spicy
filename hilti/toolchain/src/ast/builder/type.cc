// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/ast/builder/type.h"

#include <utility>

using namespace hilti;

Type hilti::builder::typeByID(::hilti::ID id, Meta m) { return hilti::type::UnresolvedID(std::move(id), std::move(m)); }
