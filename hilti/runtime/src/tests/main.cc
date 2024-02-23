// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <hilti/rt/init.h>

#define DOCTEST_CONFIG_IMPLEMENT
#include <hilti/rt/doctest.h>

struct RuntimeWrapper {
    ~RuntimeWrapper() { hilti::rt::done(); }
    RuntimeWrapper() = default;
    RuntimeWrapper(const RuntimeWrapper&) = delete;
    RuntimeWrapper(RuntimeWrapper&&) = default;
    RuntimeWrapper& operator=(const RuntimeWrapper&) = delete;
    RuntimeWrapper& operator=(RuntimeWrapper&&) = default;
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
