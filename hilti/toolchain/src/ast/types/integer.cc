// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/types/integer.h>

using namespace hilti;
using namespace hilti::type;

std::vector<Node> SignedInteger::typeParameters() const {
    return {Ctor(ctor::SignedInteger(static_cast<int64_t>(width()), 64))};
}

std::vector<Node> UnsignedInteger::typeParameters() const { return {Ctor(ctor::UnsignedInteger(width(), 64))}; }
