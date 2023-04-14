// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <cstdlib>
#include <utility>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/configuration.h>
#include <hilti/rt/global-state.h>
#include <hilti/rt/init.h>
#include <hilti/rt/logging.h>

using namespace hilti::rt;
using namespace hilti::rt::detail;

std::unique_ptr<hilti::rt::Configuration> configuration::detail::__configuration;

Configuration::Configuration() {
    auto x = ::getenv("HILTI_DEBUG");
    debug_streams = (x ? x : "");
    cout = std::cout;
}

void configuration::set(Configuration cfg) {
    if ( isInitialized() )
        hilti::rt::fatalError("attempt to change configuration after library has already been initialized");

    *detail::__configuration = std::move(cfg);
}
