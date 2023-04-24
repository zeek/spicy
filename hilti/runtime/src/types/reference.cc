// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/rt/types/reference.h"

namespace hilti::rt::reference::detail {
void throw_null() { throw NullReference("attempt to access null reference"); }
} // namespace hilti::rt::reference::detail
