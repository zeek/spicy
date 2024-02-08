// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <memory>

#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/type.h>
#include <hilti/ast/visitor.h>

using namespace hilti;

Expression::~Expression() = default;

std::string Expression::_dump() const {
    return util::fmt("%s %s", (type()->isConstant() ? " (const)" : " (non-const)"),
                     (isResolved() ? " (resolved)" : " (not resolved)"));
}
