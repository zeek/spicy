// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <hilti/hilti.h>

int main(int argc, char** argv) {
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
}
