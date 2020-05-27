// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <cstdlib>
#include <utility>

#include <hilti/rt/autogen/config.h>

#include <hilti/rt/configuration.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

Configuration::Configuration() {
    auto x = getenv("HILTI_DEBUG");
    debug_streams = (x ? x : "");
    cout = std::cout;
}

Configuration configuration::get() {
    if ( ! globalState()->configuration )
        globalState()->configuration = std::make_unique<hilti::rt::Configuration>();

    return *globalState()->configuration;
}

void configuration::set(Configuration cfg) {
    if ( isInitialized() )
        hilti::rt::fatalError("attempt to change configuration after library has already been initialized");

    *globalState()->configuration = std::move(cfg);
}
