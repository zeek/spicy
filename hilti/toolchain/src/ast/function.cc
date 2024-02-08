// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/function.h>
#include <hilti/ast/visitor.h>

using namespace hilti;

Function::~Function() = default;

std::string Function::_dump() const { return ""; }
