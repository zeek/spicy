// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>

#include <hilti/rt/util.h>

static void error(const std::string& msg) {
    std::cerr << "error: " << msg << '\n';
    exit(1);
}

static void processPreBatchedInput(std::string needle, std::istream& in, std::ostream& out) {
    std::string magic;
    std::getline(in, magic);

    if ( magic != std::string("!spicy-batch v2") )
        error("input is not a Spicy batch file");

    out << magic << '\n';

    std::set<std::string> needles = {std::move(needle)};
    auto is_needle = [&](const std::string& n) { return needles.contains(n); };

    while ( in.good() && ! in.eof() ) {
        std::string cmd;
        std::getline(in, cmd);
        cmd = hilti::rt::trim(cmd);

        if ( cmd.empty() )
            continue;

        auto m = hilti::rt::split(cmd);
        if ( m[0] == "@begin-flow" ) {
            // @begin-flow <id> <parser> <type>
            if ( m.size() != 4 )
                error("unexpected number of argument for @begin-flow");

            auto id = std::string(m[1]);
            if ( is_needle(id) )
                out << cmd << '\n';
        }
        else if ( m[0] == "@begin-conn" ) {
            // @begin-conn <conn-id> <type> <orig-id> <orig-parser> <resp-id> <resp-parser>
            if ( m.size() != 7 )
                error("unexpected number of argument for @begin-conn");


            if ( const auto& cid = std::string(m[1]); is_needle(cid) ) {
                auto orig_id = std::string(m[3]);
                auto resp_id = std::string(m[5]);
                needles.insert(std::move(orig_id));
                needles.insert(std::move(resp_id));
                out << cmd << '\n';
            }
        }

        else if ( m[0] == "@data" ) {
            // @data <id> <size>>
            // [data]\n
            if ( m.size() != 3 )
                error("unexpected number of argument for @data");

            auto id = std::string(m[1]);
            auto size = std::stoul(std::string(m[2]));

            std::string data(size, {});
            in.read(data.data(), static_cast<std::streamsize>(size));
            in.get(); // Eat newline.

            if ( in.eof() || in.fail() )
                error("premature end of @data");

            if ( is_needle(id) ) {
                out << cmd << '\n';
                out.write(data.data(), static_cast<std::streamsize>(size));
                out.put('\n');
            }
        }
        else if ( m[0] == "@end-flow" ) {
            // @end-flow <id>
            if ( m.size() != 2 )
                error("unexpected number of argument for @end-flow");

            auto id = std::string(m[1]);
            if ( is_needle(id) )
                out << cmd << '\n';
        }
        else if ( m[0] == "@end-conn" ) {
            // @end-conn <cid>
            if ( m.size() != 2 )
                error("unexpected number of argument for @end-conn");

            auto cid = std::string(m[1]);

            if ( is_needle(cid) )
                out << cmd << '\n';
        }
        else
            error(hilti::rt::fmt("unknown command '%s'", m[0]));
    }
}

// NOLINTNEXTLINE(bugprone-exception-escape)
int main(int argc, char** argv) {
    if ( argc != 2 ) {
        std::cerr << "usage: " << argv[0] << " <fid> | <cid>" << '\n';
        exit(1);
    }

    auto id = std::string(argv[1]);
    processPreBatchedInput(std::move(id), std::cin, std::cout);
    return 0;
}
