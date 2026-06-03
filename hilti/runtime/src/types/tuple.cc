// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/types/tuple.h>

using namespace hilti::rt;

void tuple::detail::throw_unset_tuple_element() { throw UnsetTupleElement("unset tuple element"); }
