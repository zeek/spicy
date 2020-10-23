// @TEST-EXEC: spicyc -c my-http.spicy >my-http.cc
// @TEST-EXEC: spicyc -l my-http.cc >my-http-linker.cc
// @TEST-EXEC: $(spicy-config --cxx) -o my-http my-http.cc my-http-linker.cc %INPUT $(spicy-config --cxxflags --ldflags)
// @TEST-EXEC: ./my-http "$(cat data)" >output
// @TEST-EXEC: btest-diff output
//
// Note: We reference this content by line numbers in the Sphinx docs, will need updating
// when anything changes.

#include <iostream>

#include <hilti/rt/libhilti.h>

#include <spicy/rt/libspicy.h>

void print(const hilti::rt::type_info::Value& v) {
    std::visit(hilti::rt::type_info::overload{
                   [&](const hilti::rt::type_info::Bytes& x) { std::cout << x.get(v); },
                   [&](const hilti::rt::type_info::ValueReference& x) { print(x.value(v)); },
                   [&](const hilti::rt::type_info::Struct& x) {
                       for ( const auto& [f, y] : x.iterate(v) ) {
                           std::cout << f.name << ": ";
                           print(y);
                           std::cout << std::endl;
                       }
                   },
                   [&](const auto& x) { assert(false); },
               },
               v.type().aux_type_info);
}

int main(int argc, char** argv) {
    assert(argc == 2);

    // Initialize runtime libraries.
    hilti::rt::init();
    spicy::rt::init();

    // Instantiate driver providing higher level parsing API.
    spicy::rt::Driver driver;

    // Print out available parsers.
    driver.listParsers(std::cout);

    // Retrieve meta object describing parser.
    auto parser = driver.lookupParser("MyHTTP::RequestLine");
    assert(parser);

    // Fill string stream with $1 as data to parse.
    std::stringstream data(argv[1]);

    // Feed data.
    auto unit = driver.processInput(**parser, data);
    assert(unit);

    // Print out conntent of parsed unit.
    print(unit->value());

    // Wrap up runtime libraries.
    spicy::rt::done();
    hilti::rt::done();

    return 0;
}

// @TEST-START-FILE my-http.spicy
module MyHTTP;

const Token      = /[^ \t\r\n]+/;
const WhiteSpace = /[ \t]+/;
const NewLine    = /\r?\n/;

type Version = unit {
    :       /HTTP\//;
    number: /[0-9]+\.[0-9]+/;
};

public type RequestLine = unit {
    method:  Token;
    :        WhiteSpace;
    uri:     Token;
    :        WhiteSpace;
    version: Version;
    :        NewLine;

    on %done {
        print self.method, self.uri, self.version.number;
        }
};
// @TEST-END-FILE

// @TEST-START-FILE data
GET /index.html HTTP/1.0

<dummy>
// @TEST-END-FILE
