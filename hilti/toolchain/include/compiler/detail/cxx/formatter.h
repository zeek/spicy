// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <vector>

#include <hilti/base/code-formatter.h>
#include <hilti/compiler/detail/cxx/elements.h>

namespace hilti::detail::cxx {

class Unit;

/** Formatter for generating C++ code. */
class Formatter : public CodeFormatter {
public:
    /**
     * Opens a new namespace that's relative to whatever the current
     * namespace is. The new namespace will go onto the formatter's namespace
     * stack.
     *
     * @param relative_ns the namespace, which will be used as is for a new
     * `namespace` directive.
     */
    void pushNamespace(std::string relative_ns);

    /** Removes the most recently opened namespace from the stack. */
    void popNamespace();

    /**
     * Enters a namespace for subsequent elements. In contrast to
     * `pushNamespace`, this takes an absolute namespace (i.e., from the root
     * level) that the method might adopt based on what the formatter's
     * current namespace is. For example, if the current namespace matches
     * the new namespace, no `namespace` directive needs to be inserted at
     * all. If the new namespace is a sub-namespace of the current one, the
     * inserted `namespace` directive will include only the relative part.
     *
     * @param absolute_ns the namespace, which will be adapted before being
     * used as part of a a `namespace` directive.
     */
    void enterNamespace(const std::string& absolute_ns);

    /** Leaves all current namespaces, clearing out the stack. */
    void leaveNamespace();

    /**
     * Returns the formatter's current absolute namespace, optionally just to
     * a given level.
     *
     * @param level max level to include, with 1 being the first.
     */
    std::optional<std::string> namespace_(int level = -1) const;

    /**
     * Adjust an ID's scoping relative to a namespace.
     *
     * @param id with absolute scoping
     * @param level depth of current namespace to consider
     * @return id with scoping relative to *level* elements of the current
     * namespacing path
     *
     */
    cxx::ID relativeID(const cxx::ID& id, int level) const;

    bool ensure_braces_for_block = true;
    bool compact_block = true;
    bool eos_after_block = false;
    bool sep_after_block = true;

private:
    std::vector<std::string> _namespaces;
};

// TODO(robin): Can we factor out these operators into code-formatter.h?
template<typename T, IF_DERIVED_FROM(T, code_formatter::isManipulator)>
inline Formatter& operator<<(Formatter& f, const T& t) {
    return t(f);
}

template<typename T, typename std::enable_if_t<std::is_scalar<T>::value>* = nullptr>
inline Formatter& operator<<(Formatter& f, const T& t) {
    f.next();
    f.stream() << t;
    return f;
}

inline Formatter& operator<<(Formatter& f, const std::string& s) {
    f.printString(s);
    return f;
}
inline Formatter& operator<<(Formatter& f, const char* s) {
    f.printString(s);
    return f;
}

namespace formatter {
using dedent = hilti::code_formatter::dedent<Formatter>;
using eol = hilti::code_formatter::eol<Formatter>;
using eos = hilti::code_formatter::eos<Formatter>;
using indent = hilti::code_formatter::indent<Formatter>;
using separator = hilti::code_formatter::separator<Formatter>;
using quoted = hilti::code_formatter::quoted<Formatter>;
using comment = hilti::code_formatter::comment<Formatter>;
} // namespace formatter

} // namespace hilti::detail::cxx
