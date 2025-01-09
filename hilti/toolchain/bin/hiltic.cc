// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <exception>

#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

int main(int argc, char** argv) try {
    hilti::init();
    hilti::Driver driver("hiltic", hilti::util::currentExecutable());

    if ( auto rc = driver.parseOptions(argc, argv); ! rc ) {
        hilti::logger().error(rc.error().description());
        return 1;
    }

    if ( auto rc = driver.run(); ! rc ) {
        hilti::logger().error(rc.error().description());

        if ( rc.error().context().size() )
            hilti::logger().error(rc.error().context());

        return 1;
    }

    return 0;
} catch ( const std::exception& e ) {
    hilti::logger().fatalError(hilti::util::fmt("terminating with uncaught exception of type %s: %s",
                                                hilti::util::demangle(typeid(e).name()), e.what()));
}
