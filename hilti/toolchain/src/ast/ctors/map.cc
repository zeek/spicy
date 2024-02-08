// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/ctors/map.h>

using namespace hilti;

ctor::map::Element::~Element() = default;

std::string ctor::map::Element::_dump() const { return ""; }
