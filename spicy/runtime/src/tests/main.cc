// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <hilti/rt/init.h>

#include <spicy/rt/init.h>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

struct RuntimeWrapper {
    ~RuntimeWrapper() {
        spicy::rt::done();
        hilti::rt::done();
    }
};

int main(int argc, char** argv) {
    doctest::Context context;
    auto rt = RuntimeWrapper();

    context.applyCommandLine(argc, argv);

    int result = context.run();

    if ( context.shouldExit() )
        return result;

    return result;
}
