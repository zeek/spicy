// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/compiler/init.h>
#include <hilti/compiler/plugin.h>

void hilti::init() {
    static bool initialized = false;

    if ( initialized )
        return;

    plugin::registry().register_(detail::createHiltiPlugin());

    initialized = true;
}
