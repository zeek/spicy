// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <spicy/rt/libspicy.h>

#include <hilti/hilti.h>

#include <spicy/spicy.h>

class Spicyc : public spicy::Driver {
public:
    Spicyc() : spicy::Driver("spicyc", hilti::util::currentExecutable()) {
        spicy::Configuration::extendHiltiConfiguration();
    }

    void hookInitRuntime() override { spicy::rt::init(); }
    void hookFinishRuntime() override { spicy::rt::done(); }
};

int main(int argc, char** argv) {
    Spicyc driver;

    if ( auto rc = driver.parseOptions(argc, argv); ! rc ) {
        hilti::logger().error(rc.error().description());
        driver.finishRuntime();
        return 1;
    }

    if ( auto rc = driver.run(); ! rc ) {
        hilti::logger().error(rc.error().description());

        if ( rc.error().context().size() )
            hilti::logger().error(rc.error().context());

        driver.finishRuntime();
        return 1;
    }
}
