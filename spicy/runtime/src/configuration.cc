// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <utility>

#include <hilti/rt/logging.h>

#include <spicy/rt/configuration.h>
#include <spicy/rt/global-state.h>
#include <spicy/rt/init.h>

using namespace spicy::rt;
using namespace spicy::rt::detail;

void configuration::set(Configuration cfg) {
    if ( isInitialized() )
        hilti::rt::fatalError("attempt to change configuration after library has already been initialized");

    globalState()->configuration = std::make_unique<spicy::rt::Configuration>(std::move(cfg));
}
