#include "spicy/ast/aliases.h"

#include <hilti/ast/types/bytes.h>
#include <hilti/ast/types/integer.h>
#include <hilti/ast/types/regexp.h>

using namespace hilti;

bool spicy::type::isBasicType(const Type& t) {
    return t.isA<type::Bytes>() || t.isA<type::RegExp>() || t.isA<type::SignedInteger>() ||
           t.isA<type::UnsignedInteger>();
}
