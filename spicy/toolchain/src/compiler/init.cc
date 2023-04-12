// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "compiler/init.h"

#include <hilti/compiler/plugin.h>

#include <spicy/compiler/plugin.h>

void spicy::init() {
    static bool initialized = false;

    if ( initialized )
        return;

    hilti::plugin::registry().register_(detail::create_spicy_plugin());

    initialized = true;
}
