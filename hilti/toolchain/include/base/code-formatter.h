// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/base/util.h>

namespace hilti {

/**
 * Base class providing support for generating "C-style" code.
 *
 * The class handles basic formatting, such as code indentation and white
 * space insertion. The main output method for user code is `printString()`.
 * For most of the formatting methods, there are corresponding i/o stream
 * manipulators so that one can writem, e.g., `my_formatter << eol();`.
 */
class CodeFormatter {
public:
    /** @param comment string beginning a comment line in the target language */
    explicit CodeFormatter(std::string comment = "//") : _comment(std::move(comment)) {}
    ~CodeFormatter() = default;

    /** Writes all output generated so far to an external stream. */
    bool output(std::ostream& out) { return util::copyStream(_out, out); }

    /** Returns a string representation of all output generated so far. */
    auto str() const { return _out.str(); }

    /** Signals the beginning of a new line. */
    void next();

    /** Inserts an empty line as a separator. */
    void separator();

    /**< Signals the end of a line. This will insert a newline. */
    void eol();

    /**< Signals the end of a statement. This will insert both a semicolon and a newline. */
    void eos();

    /** Surrounds a string with quotation mark and escapes it appropriately. */
    void quoted(const std::string& s);

    /** Inserts a comment line, prefixing it with the comment prefix. */
    void comment(const std::string& s);

    /** Increases the indentation by one level.  */
    void indent() { _indent += 1; }

    /** Decreates the indentation by one level.  */
    void dedent() { _indent -= 1; }

    /** Returns an stream with the output so far. */
    auto& stream() { return _out; }

    /** Adds a string to the output. */
    CodeFormatter& printString(const std::string& s);

    CodeFormatter(const CodeFormatter&) = delete;
    CodeFormatter(CodeFormatter&&) = delete;
    CodeFormatter& operator=(const CodeFormatter& f) = delete;
    CodeFormatter& operator=(CodeFormatter&& f) = delete;

private:
    std::stringstream _out;
    std::string _comment;

    int _indent = 0;
    bool _did_sep = true;
    bool _at_bol = true;
    bool _in_comment = false;
};

namespace code_formatter {
class isManipulator {};
} // namespace code_formatter

#define __DEFINE_MANIPULATOR0(x)                                                                                       \
    template<typename Formatter>                                                                                       \
    class x : isManipulator {                                                                                          \
    public:                                                                                                            \
        Formatter& operator()(Formatter& f) const {                                                                    \
            f.x();                                                                                                     \
            return f;                                                                                                  \
        }                                                                                                              \
    };

#define __DEFINE_MANIPULATOR1(x, t)                                                                                    \
    template<typename Formatter>                                                                                       \
    class x : isManipulator {                                                                                          \
        t _t;                                                                                                          \
                                                                                                                       \
    public:                                                                                                            \
        x(t _t) : _t(std::move(_t)) {}                                                                                 \
        Formatter& operator()(Formatter& f) const {                                                                    \
            f.x(_t);                                                                                                   \
            return f;                                                                                                  \
        }                                                                                                              \
    };

namespace code_formatter {
// NOLINTBEGIN(readability-identifier-naming)
__DEFINE_MANIPULATOR0(dedent)
__DEFINE_MANIPULATOR0(eol)
__DEFINE_MANIPULATOR0(eos)
__DEFINE_MANIPULATOR0(indent)
__DEFINE_MANIPULATOR0(separator)
__DEFINE_MANIPULATOR1(quoted, std::string)
__DEFINE_MANIPULATOR1(comment, std::string)
// NOLINTEND(readability-identifier-naming)
} // namespace code_formatter

} // namespace hilti
