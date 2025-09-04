// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/exception.h>
#include <hilti/rt/types/optional.h>

using namespace hilti::rt;

__attribute__((noreturn)) void optional::detail::throw_unset() { throw Unset(); }
__attribute__((noreturn)) void optional::detail::throw_unset_optional() { throw UnsetOptional("unset optional value"); }
