// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/meta.h>

using namespace hilti;

std::set<Location>* Meta::_cache() {
    static std::set<Location> cache;
    return &cache;
}
