// @TEST-EXEC: spicyc -g -P my-http.spicy >my-http.h
// @TEST-EXEC: spicyc -g -c my-http.spicy >my-http.cc
// @TEST-EXEC: spicyc -g -l my-http.cc >my-http-linker.cc
// @TEST-EXEC: $(spicy-config --cxx) -o my-http my-http.cc my-http-linker.cc %INPUT $(spicy-config --cxxflags --ldflags)
// @TEST-EXEC: ./my-http "$(cat data)" >output
// @TEST-EXEC: btest-diff output
//
// Note: We reference this content by line numbers in the Sphinx docs, will need updating
// when anything changes.

#include <iostream>

#include <hilti/rt/libhilti.h>
#include <spicy/rt/libspicy.h>

#include "my-http.h"

int main(int argc, char** argv) {
    assert(argc == 2);

    // Initialize runtime libraries.
    hilti::rt::init();
    spicy::rt::init();

    // Create stream with $1 as data.
    auto stream = hilti::rt::reference::make_value<hilti::rt::Stream>(argv[1]);
    stream->freeze();

    // Instantiate unit.
    auto request = hilti::rt::reference::make_value<__hlt::MyHTTP::RequestLine>();

    // Feed data.
    hlt::MyHTTP::RequestLine::parse2(request, stream, {}, {});

    // Access fields.
    std::cout << "method : " << *request->method << std::endl;
    std::cout << "uri    : " << *request->uri << std::endl;
    std::cout << "version: " << *(*request->version)->number << std::endl;

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
