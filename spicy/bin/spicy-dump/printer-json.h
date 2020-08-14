// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#pragma once

#include "options.h"

#include <ostream>
#include <string>
#include <utility>

#include <hilti/rt/json.h>
#include <hilti/rt/type-info.h>

/** Render parsed unit into JSON representation. */
class JSONPrinter {
public:
    /**
     * Constructor.
     *
     * @param output stream to send output to
     * @param options output controlling specifics of the output
     */
    JSONPrinter(std::ostream& output, OutputOptions options) : _output(output), _options(std::move(options)){};

    /**
     * Render one parsed value into JSON.
     *
     * @param v value representing parsed unit to render
     */
    void print(const hilti::rt::type_info::Value& v);

private:
    // Return output stream.
    std::ostream& out() { return _output; }

    nlohmann::json convert(const hilti::rt::type_info::Value& v);

    std::ostream& _output;
    OutputOptions _options;
};
