// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <pwd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <utf8proc/utf8proc.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <hilti/rt/backtrace.h>
#include <hilti/rt/util.h>

#include <hilti/base/logger.h>
#include <hilti/base/util.h>

// We include pathfind directly here so we do not have to work
// around it being installed by its default install target.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wpessimizing-move"
// NOLINTNEXTLINE(bugprone-suspicious-include)
#include <pathfind/src/pathfind.cpp>
#pragma GCC diagnostic pop

using namespace hilti;
using namespace hilti::util;

void detail::__internal_error(const std::string& s) { logger().internalError(s); }

void util::cannot_be_reached() { hilti::logger().internalError("code is executing that should not be reachable"); }

std::vector<std::string> util::split(std::string s, const std::string& delim) {
    std::vector<std::string> l;

    while ( true ) {
        size_t p = s.find(delim);

        if ( p == std::string::npos )
            break;

        l.push_back(s.substr(0, p));

        // FIXME: Don't understand why directly assigning to s doesn't work.
        std::string t = s.substr(p + delim.size(), std::string::npos);
        s = t;
    }

    l.push_back(s);
    return l;
}

std::pair<std::string, std::string> util::split1(std::string s, const std::string& delim) {
    if ( auto i = s.find(delim); i != std::string::npos )
        return std::make_pair(s.substr(0, i), s.substr(i + delim.size()));

    return std::make_pair(std::move(s), "");
}

std::pair<std::string, std::string> util::rsplit1(std::string s, const std::string& delim) {
    if ( auto i = s.rfind(delim); i != std::string::npos )
        return std::make_pair(s.substr(0, i), s.substr(i + delim.size()));

    return std::make_pair("", std::move(s));
}

std::string util::replace(const std::string& s, const std::string& o, const std::string& n) {
    if ( o.empty() )
        return s;

    auto x = s;

    size_t i = 0;
    while ( (i = x.find(o, i)) != std::string::npos ) {
        x.replace(i, o.length(), n);
        i += n.length();
    }

    return x;
}

std::string util::tolower(const std::string& s) {
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    return t;
}

std::string util::toupper(const std::string& s) {
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::toupper);
    return t;
}

std::string util::rtrim(const std::string& s) {
    auto t = s;
    t.erase(std::find_if(t.rbegin(), t.rend(), [](char c) { return ! std::isspace(c); }).base(), t.end());
    return t;
}

std::string util::ltrim(const std::string& s) {
    auto t = s;
    t.erase(t.begin(), std::find_if(t.begin(), t.end(), [](char c) { return ! std::isspace(c); }));
    return t;
}

std::string util::trim(const std::string& s) { return ltrim(rtrim(s)); }

uint64_t util::hash(const std::string& str) { return util::hash(str.data(), str.size()); }

uint64_t util::hash(const char* data, size_t len) {
    uint64_t h = 0;

    while ( len-- )
        h = (h << 5U) - h + static_cast<uint64_t>(*data++);

    return h;
}

std::string util::uitoa_n(uint64_t value, unsigned int base, int n) {
    static char dig[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    assert(base <= strlen(dig));

    std::string s;

    do {
        s.append(1, dig[value % base]);
        value /= base;
    } while ( value && (n < 0 || s.size() < static_cast<size_t>(n) - 1) );

    return s;
}

bool util::endsWith(const std::string& s, const std::string& suffix) {
    size_t i = s.rfind(suffix);

    if ( i == std::string::npos )
        return false;

    return (i == (s.length() - suffix.size()));
}

hilti::Result<hilti::rt::filesystem::path> util::findInPaths(const hilti::rt::filesystem::path& file,
                                                             const std::vector<hilti::rt::filesystem::path>& paths) {
    if ( file.is_absolute() ) {
        if ( hilti::rt::filesystem::exists(file) )
            return file;

        return hilti::result::Error(fmt("absolute path %s does not exist", file));
    }

    for ( const auto& d : paths ) {
        auto p = d / file;
        if ( hilti::rt::filesystem::exists(p) )
            return p;
    }

    return hilti::result::Error(fmt("%s not found", file));
}

hilti::rt::filesystem::path util::currentExecutable() {
    const auto exe = PathFind::FindExecutable();

    if ( exe.empty() ) {
        auto msg = std::string("could not determine path of current executable");

#if defined(__FreeBSD__)
        if ( ! rt::filesystem::exists("/proc") || rt::filesystem::is_empty("/proc") )
            msg += ": /proc needs to be mounted";
#endif

        rt::internalError(msg);
    }

    return normalizePath(exe);
}

void util::abort_with_backtrace() {
    std::cerr << "\n--- Aborting" << std::endl;
    auto bt = hilti::rt::Backtrace().backtrace();
    for ( const auto& f : *bt )
        std::cerr << f << std::endl;
    abort();
}

double util::currentTime() {
    struct timeval tv {};
    gettimeofday(&tv, nullptr);
    return static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1e6;
}

std::string util::toIdentifier(const std::string& s, bool ensure_non_keyword) {
    static char const* const hex = "0123456789abcdef";

    if ( s.empty() )
        return s;

    std::string normalized = s;

    normalized = replace(normalized, "::", "_");
    normalized = replace(normalized, ":", "_");
    normalized = replace(normalized, ">", "_");
    normalized = replace(normalized, ",", "_");
    normalized = replace(normalized, ".", "_");
    normalized = replace(normalized, " ", "_");
    normalized = replace(normalized, "-", "_");
    normalized = replace(normalized, "'", "_");
    normalized = replace(normalized, "\"", "_");
    normalized = replace(normalized, "__", "_");

    while ( ::util::endsWith(normalized, "_") )
        normalized = normalized.substr(0, normalized.size() - 1);

    std::string ns;

    for ( auto c : normalized ) {
        if ( isalnum(c) || c == '_' ) {
            ns += c;
            continue;
        }

        ns += "x";
        ns += hex[c >> 4U];
        ns += hex[c % 0x0f];
    }

    ns = replace(ns, "__", "_");

    if ( isdigit(ns[0]) )
        ns = "_" + ns;

    if ( ensure_non_keyword )
        ns += "_";

    return ns;
}

std::string util::prefixParts(const std::string& in, const std::string& prefix, const std::string& include_tag) {
    if ( in.empty() )
        return "";

    auto x = transform(split(in, " "), [&](auto s) {
        if ( s.empty() )
            return std::string();

        if ( include_tag.size() ) {
            auto x = split(s, "!");
            if ( x.size() == 3 ) {
                if ( x[1] != include_tag )
                    return std::string();

                s = x[2];
            }
        }

        if ( auto x = trim(s); ! util::startsWith(s, "-") )
            return prefix + x;
        else
            return x;
    });

    return join(filter(x, [](auto s) -> bool { return s.size(); }), " ");
}

std::vector<std::string> util::flattenParts(const std::vector<std::string>& in) {
    std::vector<std::string> out;

    for ( const auto& i : in ) {
        for ( auto s : util::split(i) ) {
            s = util::trim(s);
            if ( s.empty() )
                continue;

            out.push_back(s);
        }
    }

    return out;
}

std::optional<hilti::rt::filesystem::path> util::cacheDirectory(const hilti::Configuration& configuration) {
    // If we are executing from the build directory, the cache is also located
    // there; else it lives in a versioned folder in the user's `$HOME/.cache/spicy`.
    if ( configuration.uses_build_directory )
        return configuration.build_directory / "cache" / "spicy";

    if ( auto spicy_cache = ::getenv("SPICY_CACHE") )
        return spicy_cache;

    const char* homedir = getenv("HOME");

    if ( homedir == nullptr ) {
        auto pwuid = getpwuid(getuid());
        if ( ! pwuid )
            return {};

        homedir = pwuid->pw_dir;
    }

    if ( homedir )
        return rt::filesystem::path(rt::filesystem::path(homedir) / ".cache" / "spicy" / configuration.version_string);

    return {};
}
