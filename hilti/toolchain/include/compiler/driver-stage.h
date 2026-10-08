// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

namespace hilti::driver {

/** Stages of the compilation pipeline. */
enum class Stage { UNINITIALIZED, INITIALIZED, RESOLVED, COMPILED, CODEGENED, LINKED, JITTED };

} // namespace hilti::driver
