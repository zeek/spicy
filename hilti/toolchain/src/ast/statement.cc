// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/statement.h>
#include <hilti/ast/visitor.h>

using namespace hilti;

Statement::~Statement() = default;

std::string Statement::_dump() const { return ""; }
