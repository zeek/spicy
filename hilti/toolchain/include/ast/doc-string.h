// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

namespace hilti {

namespace printer {
class Stream;
}

/** Represents an AST node's documentation string. */
class DocString {
public:
    /**
     * Returns all lines of summary text added so far. The returned lines will
     * have their comment prefixes stripped.
     */
    const auto& summary() const { return _summary; }

    /**
     * Returns all lines of documentation text added so far. The returned lines
     * will have their comment prefixes stripped.
     */
    const auto& text() const { return _text; }

    /**
     * Appends a line of summary text to the documentation.
     *
     * @param line line to add, with optional comment prefix (which will be removed)
     */
    void addSummary(const std::string& line) { _summary.push_back(normalize(line)); }

    /**
     * Appends a line of documentation text to the documentation.
     *
     * @param line line to add, with optional comment prefix (which will be removed)
     */
    void addText(const std::string& line) { _text.push_back(normalize(line)); }

    /**
     * Renders the comment back into a multi-line string. This is primarily for debugging.
     */
    void render(std::ostream& out) const;

    /**
     * Renders the comment back into a code representation through our code
     * printer.
     */
    void render(printer::Stream& out) const;

    /** Returns true if any summary or documentation text has been added. */
    explicit operator bool() const { return ! (_summary.empty() && _text.empty()); }

private:
    // Removes any comment prefix from a line.
    std::string normalize(std::string line) const;

    std::vector<std::string> _summary;
    std::vector<std::string> _text;
};

} // namespace hilti
