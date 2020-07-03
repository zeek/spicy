// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <spicy/rt/libspicy.h>

#include <hilti/hilti.h>

#include <spicy/spicy.h>

class Spicyc : public hilti::Driver {
public:
    Spicyc(const std::string_view& argv0 = "") : hilti::Driver("spicyc", argv0) {
        spicy::Configuration::extendHiltiConfiguration();
    }

    void hookInitRuntime() override { spicy::rt::init(); }
    void hookFinishRuntime() override { spicy::rt::done(); }
};

int main(int argc, char** argv) {
    Spicyc driver;

    if ( auto rc = driver.parseOptions(argc, argv); ! rc ) {
        hilti::logger().error(rc.error().description());
        exit(1);
    }

    if ( auto rc = driver.run(); ! rc ) {
        hilti::logger().error(rc.error().description());
        exit(1);
    }

    return 0;
}
