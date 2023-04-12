// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <hilti/base/result.h>

namespace hilti::util {
/**
 * Helper to preprocess @if/@else/@endif directives in lines of input.
 *
 * This currently supports the following set of directives:
 *
 *     - `@if [!] <id> ==|!=|<|<=|>|>= <integer>
 *     - `@if [!] <id>
 *     - `@else`
 *     - `@endif`
 **/
class SourceCodePreprocessor {
public:
    using ID = std::string; //< type for identifiers
    using Value = int;      //< type associated with integers (may expand this to a variant in the future)

    /** Current inclusion state while processing input. */
    enum class State {
        Include, //< include line
        Skip     //< skip line
    };

    /**
     * Constructor.
     *
     * @param constants map of constants that preprocessor directives can work on
     */
    SourceCodePreprocessor(std::map<ID, Value> constants) : _constants(std::move(std::move(constants))) {}

    /**
     * Process one preprocessor directive of the form `@<id> [expression]`.
     *
     * This evaluates the directive and updates internal state accordingly.
     *
     * @param directive a supported directive ID, which must start with `@`.
     * @param expression string with expression that the directive is taking
     * @result the new inclusion state for subsequent input, or an error if the directive could not be processed
     */
    Result<State> processLine(std::string_view directive, std::string_view expression = "");

    /** Returns the current inclusion state. */
    State state() const { return _stack.back() == 1 ? State::Include : State::Skip; }

    /**
     * Returns true if the proprocessor expects further directives that closed
     * previously opened blocks
     */
    bool expectingDirective() { return _stack.size() > 1; }

private:
    Result<bool> _parseIf(const std::string_view& expression);

    std::map<ID, Value> _constants;
    std::vector<int> _stack = {1};
};

} // namespace hilti::util
