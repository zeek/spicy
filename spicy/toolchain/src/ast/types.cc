// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "spicy/ast/types.h"

#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/regexp.h>

bool spicy::type::supportsLiterals(const hilti::Type& t) {
    return t.isA<hilti::type::Bytes>() || t.isA<hilti::type::RegExp>() || t.isA<hilti::type::SignedInteger>() ||
           t.isA<hilti::type::UnsignedInteger>();
}
