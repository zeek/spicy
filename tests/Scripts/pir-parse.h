// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

// For fixtures that inspect returned cursor offsets or exception classes, which spicy-driver does not expose.
// The fixture sets error_style: 0 = outcome only, 1 = description, 2 = exception class and description.
#pragma once

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <hilti/rt/libhilti.h>
#include <spicy/rt/driver.h>
#include <spicy/rt/libspicy.h>

struct Piece {
    std::string bytes;
    uint64_t gap = 0;
};

class ParsingState : public spicy::rt::driver::ParsingState {
public:
    using spicy::rt::driver::ParsingState::ParsingState;

protected:
    void debug(const std::string&) final {}
};

static void run(const char* name, const char* label, const std::vector<Piece>& pieces, size_t chunk = 0) {
    auto parser = spicy::rt::lookupParser(hilti::rt::String(name));
    if ( ! parser )
        throw std::runtime_error("no parser " + std::string(name));
    ParsingState state(spicy::rt::driver::ParsingType::Stream, *parser);
    auto error = [&](const char* type, const std::exception& e) {
        std::cout << label;
        if ( error_style == 2 )
            std::cout << " " << type << ": " << e.what();
        else if ( error_style == 1 )
            std::cout << " error: " << e.what();
        else
            std::cout << " error";
        std::cout << std::endl;
    };
    try {
        for ( const auto& piece : pieces ) {
            if ( piece.gap ) {
                state.process(piece.gap, nullptr);
                continue;
            }
            for ( size_t i = 0; i < piece.bytes.size(); i += chunk ? chunk : piece.bytes.size() ) {
                auto n = std::min(chunk ? chunk : piece.bytes.size(), piece.bytes.size() - i);
                state.process(n, piece.bytes.data() + i);
            }
        }
        if ( auto offset = state.finish() )
            std::cout << label << " ok offset=" << *offset << std::endl;
        else
            std::cout << label << " waiting" << std::endl;
    } catch ( const spicy::rt::ParseError& e ) {
        error("ParseError", e);
    } catch ( const hilti::rt::MissingData& e ) {
        error("MissingData", e);
    } catch ( const std::exception& e ) {
        error("other", e);
    }
}

static std::string be64(uint64_t n) {
    std::string x(8, '\0');
    for ( int i = 7; i >= 0; --i ) {
        x[i] = static_cast<char>(n & 255);
        n >>= 8;
    }
    return x;
}

extern "C" int HILTI_EXPORT hilti_main();

int main() {
    hilti::rt::init();
    spicy::rt::init();
    auto result = hilti_main();
    hilti::rt::done();
    return result;
}
