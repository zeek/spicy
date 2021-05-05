#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>

#include <hilti/rt/exception.h>
#include <hilti/rt/init.h>
#include <hilti/rt/types/reference.h>
#include <hilti/rt/types/stream.h>
#include <hilti/rt/util.h>

#include <spicy/rt/init.h>
#include <spicy/rt/parsed-unit.h>
#include <spicy/rt/parser.h>

std::optional<std::string> name;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    static const spicy::rt::Parser* parser = nullptr;

    if ( ! parser ) {
        hilti::rt::init();
        spicy::rt::init();

        for ( auto* p : spicy::rt::parsers() ) {
            parser = p;
            if ( name && p->name == *name )
                break;
        }
    }

    assert(parser);

    hilti::rt::ValueReference<hilti::rt::Stream> stream;
    stream->append(reinterpret_cast<const char*>(Data), Size);

    hilti::rt::ValueReference<spicy::rt::ParsedUnit> pu;

    try {
        if ( parser->parse1 )
            parser->parse1(stream, {}, {});
        else if ( parser->parse3 )
            parser->parse3(pu, stream, {}, {});
    } catch ( ... ) {
    }

    return 0; // Non-zero return values are reserved for future use.
}

extern "C" int LLVMFuzzerRunDriver(int* argc, char*** argv, int (*UserCb)(const uint8_t* Data, size_t Size));

// We provide our own `main` to avoid linking to hilti-rt's weak `main` symbol.
int main(int argc, char** argv) {
    if ( const char* n = std::getenv("SPICY_FUZZ_PARSER") )
        name = n;

    LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}
