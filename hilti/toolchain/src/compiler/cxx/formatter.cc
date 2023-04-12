// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <cassert>

#include <hilti/compiler/detail/cxx/formatter.h>

using namespace hilti::detail::cxx;
using namespace hilti::detail::cxx::formatter;

void Formatter::pushNamespace(std::string relative_ns) {
    auto& f = *this;
    f.separator();

    if ( util::startsWith(relative_ns, "::") )
        relative_ns = relative_ns.substr(2);

    if ( util::endsWith(relative_ns, "::") ) {
        assert(relative_ns != "::");
        // Add an anonymous namespace.
        f << "namespace " << relative_ns.substr(0, relative_ns.size() - 2) << " { namespace {";
        f.indent();
        f.eol();
    }
    else if ( relative_ns.size() ) {
        f << "namespace " << relative_ns << " {";
        f.indent();
        f.eol();
    }

    _namespaces.push_back(relative_ns);
}

void Formatter::enterNamespace(const std::string& absolute_ns) {
    while ( ! _namespaces.empty() ) {
        auto current = util::split(util::join(_namespaces, "::"), "::");
        auto target = util::split(absolute_ns, "::");

        auto i = 0UL;
        while ( i < std::min(target.size(), current.size()) && target[i] == current[i] ) {
            i++;
        }

        if ( i == target.size() && i == current.size() )
            // No change.
            return;

        if ( i >= current.size() ) {
            pushNamespace(util::join(util::slice(target, static_cast<int>(i)), "::"));
            return;
        }

        popNamespace();
    }

    pushNamespace(absolute_ns);
}

void Formatter::popNamespace() {
    assert(_namespaces.size());

    auto& f = *this;
    const auto& ns = _namespaces.back();

    if ( ns.size() ) {
        f.dedent();

        if ( util::endsWith(ns, "::") )
            f << "} }";
        else
            f << '}';

        f.eol();
    }

    f.separator();
    _namespaces.pop_back();
}

std::optional<std::string> Formatter::namespace_(int level) const {
    if ( ! _namespaces.empty() )
        return util::join(util::slice(_namespaces, level), "::");

    return {};
}

void Formatter::leaveNamespace() {
    while ( ! _namespaces.empty() )
        popNamespace();
}

hilti::detail::cxx::ID Formatter::relativeID(const cxx::ID& id, int level) const {
    auto ns = cxx::ID{util::join(util::slice(_namespaces, level - 1), "::")};
    return id.relativeTo(ns);
}
