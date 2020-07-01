// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include <iostream>
#include <string>

#include <hilti/rt/result.h>

#include <spicy/rt/parser.h>

namespace spicy::rt {

/**
 * Runtime driver to retrieve and feed Spicy parsers.
 *
 * The HILTI/Spocy runtime environments must be managed externally, and must
 * have been initialized already before using any of the driver's
 * functionality.
 */
class Driver {
public:
    Driver() : _enable_debug(hilti::rt::isDebugVersion()) {}
    /**
     * Prints a humand-readable list of all available parsers, retrieved from
     * the Spicy runtime system.
     *
     * @param out stream to print the summary to
     * @return an error if the list cannot be retrieved
     */
    hilti::rt::Result<hilti::rt::Nothing> listParsers(std::ostream& out);

    /**
     * Retrieves a parser by its name.
     *
     * @param parser_name name of the parser to be retrieved, as shown in the
     * output of `listParsers()`. If none is given and there's only one
     * available, that one is taken.
     *
     * @return the parser, or an error if it could not be retrieved
     */
    hilti::rt::Result<const spicy::rt::Parser*> lookupParser(const std::string& parser_name = "");

    /**
     * Feeds a parser with an input stream of data.
     *
     * @param parser parser to instantiate and feed
     * @param in stream to read input data from; will read until EOF is encountered
     * @param increment if non-zero, will feed the data in small chunks at a
     * time; this is mainly for testing parsers; incremental parsing
     *
     * @return error if the input couldn't be fed to the parser (excluding parse errors)
     * @throws HILTI or Spocy runtime error if the parser into trouble
     */
    hilti::rt::Result<spicy::rt::ParsedUnit> processInput(const spicy::rt::Parser& parser, std::istream& in,
                                                          int increment = 0);

private:
    void _debug(const std::string_view& msg);
    void _debug_stats(const hilti::rt::ValueReference<hilti::rt::Stream>& data);

    bool _enable_debug = false;
};

} // namespace spicy::rt
