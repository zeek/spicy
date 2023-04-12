// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "ast/types/library.h"

#include <utility>

#include <hilti/base/util.h>

using namespace hilti;
using namespace hilti::type;

static std::string normalize(std::string cxx_name) {
    if ( ! util::startsWith(cxx_name, "::") )
        return util::fmt("::%s", cxx_name);

    return cxx_name;
}

Library::Library(std::string cxx_name, Meta m) : TypeBase(std::move(m)), _cxx_name(normalize(std::move(cxx_name))) {}
