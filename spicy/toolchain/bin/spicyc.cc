// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <spicy/rt/libspicy.h>

#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

#include <spicy/autogen/config.h>
#include <spicy/compiler/driver.h>
#include <spicy/compiler/init.h>

class Spicyc : public spicy::Driver {
public:
    Spicyc(std::string_view argv0) : spicy::Driver("spicyc", hilti::util::currentExecutable(argv0)) {
        spicy::Configuration::extendHiltiConfiguration();
    }

    void hookInitRuntime() override { spicy::rt::init(); }
    void hookFinishRuntime() override { spicy::rt::done(); }
};

int main(int argc, char** argv) try {
    hilti::init();
    spicy::init();

    Spicyc driver(argv[0]);

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
} catch ( const std::exception& e ) {
    hilti::logger().fatalError(hilti::util::fmt("terminating with uncaught exception of type %s: %s",
                                                hilti::util::demangle(typeid(e).name()), e.what()));
}
