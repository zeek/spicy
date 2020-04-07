#include <iostream>

#include <hilti/rt/libhilti.h>
#include <spicy/rt/libspicy.h>

using spicy::rt::fmt;

int main(int argc, char** argv) {
    hilti::rt::init();
    spicy::rt::init();

    spicy::rt::Driver driver;
    auto parser = driver.lookupParser("MyHTTP::RequestLine");
    assert(parser);

    try {
        std::ifstream in("/dev/stdin", std::ios::in);
        driver.processInput(**parser, in);
    } catch ( const std::exception& e ) {
        std::cerr << e.what() << std::endl;
    }

    spicy::rt::done();
    hilti::rt::done();
    return 0;
}
