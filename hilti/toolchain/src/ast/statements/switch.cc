// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/ast/statements/switch.h>

using namespace hilti;

statement::switch_::Case::~Case() = default;

std::string statement::switch_::Case::_dump() const { return ""; }
