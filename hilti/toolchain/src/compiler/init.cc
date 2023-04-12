// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "compiler/init.h"

#include <hilti/compiler/plugin.h>

void hilti::init() {
    static bool initialized = false;

    if ( initialized )
        return;

    plugin::registry().register_(detail::create_hilti_plugin());

    initialized = true;
}
