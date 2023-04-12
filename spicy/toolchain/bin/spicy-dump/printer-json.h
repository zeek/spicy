// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <ostream>
#include <utility>

#include <hilti/rt/json-fwd.h>
#include <hilti/rt/type-info.h>
#include <hilti/rt/types/integer.h>

#include "options.h"

/** Render parsed unit into JSON representation. */
class JSONPrinter {
public:
    /**
     * Constructor.
     *
     * @param output stream to send output to
     * @param options output controlling specifics of the output
     */
    JSONPrinter(std::ostream& output, OutputOptions options) : _output(output), _options(options){};

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
