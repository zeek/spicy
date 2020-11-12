// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <stdlib.h>

#include <iostream>
#include <string>

#include <hilti/rt/util.h>

void error(const std::string& msg) {
    std::cerr << "error: " << msg << std::endl;
    exit(1);
}

void processPreBatchedInput(std::string needle, std::istream& in, std::ostream& out) {
    std::string magic;
    std::getline(in, magic);

    if ( magic != std::string("!spicy-batch v1") )
        error("input is not a Spicy batch file");

    out << magic << std::endl;

    while ( in.good() && ! in.eof() ) {
        std::string cmd;
        std::getline(in, cmd);
        cmd = hilti::rt::trim(cmd);

        if ( cmd.empty() )
            continue;

        auto m = hilti::rt::split(cmd);
        if ( m[0] == "@begin" ) {
            // @begin <id> <parser> <type>
            if ( m.size() != 4 )
                error("unexpected number of argument for @begin");

            auto id = std::string(m[1]);
            if ( id == needle )
                out << cmd << std::endl;
        }
        else if ( m[0] == "@data" ) {
            // @begin <id> <size>>p
            // [data]\n
            if ( m.size() != 3 )
                error("unexpected number of argument for @data");

            auto id = std::string(m[1]);
            auto size = std::stoul(std::string(m[2]));

            char data[size];
            in.read(data, size);
            in.get(); // Eat newline.

            if ( in.eof() || in.fail() )
                error("premature end of @data");

            if ( id == needle ) {
                out << cmd << std::endl;
                out.write(data, size);
                out.put('\n');
            }
        }
        else if ( m[0] == "@end" ) {
            // @end <id>
            if ( m.size() != 2 )
                error("unexpected number of argument for @end");

            auto id = std::string(m[1]);
            if ( id == needle )
                out << cmd << std::endl;
        }
        else
            error(hilti::rt::fmt("unknown command '%s'", m[0]));
    }
}

int main(int argc, char** argv) {
    if ( argc != 2 ) {
        std::cerr << "usage: " << argv[0] << " <id>" << std::endl;
        exit(1);
    }

    auto id = std::string(argv[1]);
    processPreBatchedInput(id, std::cin, std::cout);
    return 0;
}
