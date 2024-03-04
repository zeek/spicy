// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/compiler/plugin.h>

#include <spicy/compiler/detail/plugin.h>
#include <spicy/compiler/init.h>

void spicy::init() {
    static bool initialized = false;

    if ( initialized )
        return;

    hilti::plugin::registry().register_(detail::createSpicyPlugin());

    initialized = true;
}
