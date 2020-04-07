// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <iostream>

#include <hilti/compiler/context.h>
#include <hilti/compiler/jit.h>

int main(int argc, char** argv) {
    if ( argc != 2 ) {
        std::cerr << "Usage: jit-test <file.cc>" << std::endl;
        return 1;
    }

    hilti::CxxCode code(argv[1]);

    if ( ! code.isLoaded() ) {
        std::cerr << "Could not load source file" << std::endl;
        return 1;
    }

    hilti::Options options;
    auto ctx = std::make_shared<hilti::Context>(options);

    hilti::JIT compiler(ctx);
    compiler.add(code);

    if ( ! compiler.compile() ) {
        std::cerr << "Could not compile source file" << std::endl;
        return 1;
    }

    return 0;
}
