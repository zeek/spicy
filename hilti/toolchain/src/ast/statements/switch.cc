// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/statements/switch.h>

using namespace hilti;

statement::switch_::Case::~Case() = default;

std::string statement::switch_::Case::_dump() const { return ""; }
