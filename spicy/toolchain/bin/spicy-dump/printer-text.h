// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <ostream>
#include <string>
#include <utility>

#include <hilti/rt/type-info.h>

#include "options.h"

/** Render parsed unit into readable text representation. */
class TextPrinter {
public:
    /**
     * Constructor.
     *
     * @param output stream to send output to
     * @param options output controlling specifics of the output
     */
    TextPrinter(std::ostream& output, OutputOptions options) : _output(output), _options(options) {}

    /**
     * Render one parsed value into text.
     *
     * @param v value representing parsed unit to render
     */
    void print(const hilti::rt::type_info::Value& v);

private:
    // Return output stream.
    std::ostream& out() { return _output; }

    // Append rendering of offsets to current output line.
    void printOffsets(const hilti::rt::type_info::Struct& ti, const hilti::rt::type_info::Value& v,
                      const std::string& field_name);

    // Insert current indentation into output stream.
    void outputIndent() { out() << std::string(static_cast<std::basic_string<char>::size_type>(_level) * 2, ' '); }

    // Increase indentation level while executing callback function.
    template<typename Func>
    void indent(Func&& func) {
        ++_level;
        func();
        --_level;
    }

    std::ostream& _output;  // output stream
    OutputOptions _options; // formatting options
    int _level = 0;         // indentation level
};
