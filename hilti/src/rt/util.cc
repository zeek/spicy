// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <limits.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include <hilti/3rdparty/utf8proc/utf8proc.h>

#include <hilti/rt/autogen/version.h>

#include <hilti/rt/autogen/config.h>

#include <hilti/rt/backtrace.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/util.h>

std::string hilti::rt::version() {
    constexpr char hilti_version[] = PROJECT_VERSION_STRING_LONG;

#if HILTI_RT_BUILD_TYPE_DEBUG
    return hilti::rt::fmt("HILTI runtime library version %s [debug build]", hilti_version);
#elif HILTI_RT_BUILD_TYPE_RELEASE
    return hilti::rt::fmt("HILTI runtime library version %s [release build]", hilti_version);
#else
#error "Neither HILTI_RT_BUILD_TYPE_DEBUG nor HILTI_RT_BUILD_TYPE_RELEASE define."
#endif
}

bool hilti::rt::isDebugVersion() {
#if HILTI_RT_BUILD_TYPE_DEBUG
    return true;
#elif HILTI_RT_BUILD_TYPE_RELEASE
    return false;
#else
#error "Neither HILTI_RT_BUILD_TYPE_DEBUG nor HILTI_RT_BUILD_TYPE_RELEASE define."
#endif
}

void hilti::rt::abort_with_backtrace() {
    fputs("\n--- Aborting in libhilti\n", stderr);
    hilti::rt::Backtrace bt;
    for ( const auto& f : bt.backtrace() )
        std::cerr << f << std::endl;
    abort();
}

void hilti::rt::cannot_be_reached() { hilti::rt::internalError("code is executing that should not be reachable"); }

hilti::rt::MemoryStatistics hilti::rt::memory_statistics() {
    MemoryStatistics stats;

    struct rusage r;
    getrusage(RUSAGE_SELF, &r);
    auto fibers = detail::Fiber::statistics();

    stats.memory_heap = r.ru_maxrss * 1024;
    stats.num_fibers = fibers.current;
    stats.max_fibers = fibers.max;
    stats.cached_fibers = fibers.cached;

    return stats;
}

hilti::rt::Result<std::filesystem::path> hilti::rt::createTemporaryFile(const std::string& prefix) {
    std::error_code ec;
    auto tmp_dir = std::filesystem::temp_directory_path(ec);

    if ( ec )
        return hilti::rt::result::Error(fmt("could not create temporary file: %s", ec.message()));

    auto template_ = (tmp_dir / (prefix + "-XXXXXX")).native();

    auto handle = ::mkstemp(template_.data());
    if ( handle == -1 )
        return hilti::rt::result::Error(fmt("could not create temporary file in '%s': %s", tmp_dir, strerror(errno)));

    ::close(handle);

    return std::filesystem::path(template_);
}

std::filesystem::path hilti::rt::normalizePath(const std::filesystem::path& p) {
    if ( p.empty() )
        return "";

    if ( ! std::filesystem::exists(p) )
        return p;

    char buffer[PATH_MAX];
    return realpath(std::filesystem::absolute(p).native().c_str(), buffer);
}

std::vector<std::string_view> hilti::rt::split(std::string_view s, std::string_view delim) {
    if ( delim.empty() )
        return {s};

    if ( s.size() < delim.size() )
        return {s};

    std::vector<std::string_view> l;

    const bool ends_in_delim = (s.substr(s.size() - delim.size()) == delim);

    do {
        size_t p = s.find(delim);
        l.push_back(s.substr(0, p));
        if ( p == std::string_view::npos )
            break;

        s.remove_prefix(p + delim.size());
    } while ( ! s.empty() );

    if ( ends_in_delim )
        l.push_back("");

    return l;
}

std::vector<std::string_view> hilti::rt::split(std::string_view s) {
    std::vector<std::string_view> l;

    s = trim(s);

    while ( ! s.empty() ) {
        size_t p = s.find_first_of(detail::whitespace_chars);
        l.push_back(s.substr(0, p));
        if ( p == std::string_view::npos )
            break;

        s.remove_prefix(p + 1);
        s = ltrim(s);
    }

    return l;
}

std::pair<std::string, std::string> hilti::rt::split1(std::string s) {
    if ( auto i = s.find_first_of(detail::whitespace_chars); i != std::string::npos )
        return std::make_pair(s.substr(0, i), std::string(ltrim(s.substr(i + 1))));

    return std::make_pair(std::move(s), "");
}

std::pair<std::string, std::string> hilti::rt::rsplit1(std::string s) {
    if ( auto i = s.find_last_of(detail::whitespace_chars); i != std::string::npos )
        return std::make_pair(s.substr(0, i), std::string(rtrim(s.substr(i + 1))));

    return std::make_pair("", std::move(s));
}

std::pair<std::string, std::string> hilti::rt::split1(std::string s, const std::string& delim) {
    if ( auto i = s.find(delim); i != std::string::npos )
        return std::make_pair(s.substr(0, i), s.substr(i + delim.size()));

    return std::make_pair(std::move(s), "");
}

std::pair<std::string, std::string> hilti::rt::rsplit1(std::string s, const std::string& delim) {
    if ( auto i = s.rfind(delim); i != std::string::npos )
        return std::make_pair(s.substr(0, i), s.substr(i + delim.size()));

    return std::make_pair("", std::move(s));
}

// In-place implementation copies chars shrinking escape sequences to binary.
// Requires that binary results are not larger than their escape sequence.
std::string hilti::rt::expandEscapes(std::string s) {
    auto d = s.begin();
    for ( auto c = d; c != s.end(); ) {
        if ( *c != '\\' ) {
            *d++ = *c++;
            continue;
        }

        ++c;

        if ( c == s.end() )
            throw Exception("broken escape sequence");

        switch ( *c++ ) {
            case '\\': *d++ = '\\'; break;

            case '"': *d++ = '"'; break;

            case 'n': *d++ = '\n'; break;

            case 'r': *d++ = '\r'; break;

            case 't': *d++ = '\t'; break;

            case 'u': {
                auto end = c + 4;
                if ( end > s.end() )
                    throw Exception("incomplete unicode \\u");
                utf8proc_int32_t val;
                c = atoi_n(c, end, 16, &val);

                if ( c != end )
                    throw Exception("cannot decode character");

                uint8_t tmp[4];
                int len = utf8proc_encode_char(val, tmp);

                if ( ! len )
                    throw Exception("cannot encode unicode code point");

                d = std::copy(tmp, tmp + len, d);
                break;
            }

            case 'U': {
                auto end = c + 8;
                if ( end > s.end() )
                    throw Exception("incomplete unicode \\U");
                utf8proc_int32_t val;
                c = atoi_n(c, end, 16, &val);

                if ( c != end )
                    throw Exception("cannot decode character");

                uint8_t tmp[4];
                int len = utf8proc_encode_char(val, tmp);

                if ( ! len )
                    throw Exception("cannot encode unicode code point");

                d = std::copy(tmp, tmp + len, d);
                break;
            }

            case 'x': {
                auto end = std::min(c + 2, s.end());
                if ( c == s.end() )
                    throw Exception("\\x used with no following hex digits");
                char val;
                c = atoi_n(c, end, 16, &val);

                if ( c != end )
                    throw Exception("cannot decode character");

                *d++ = val;
                break;
            }

            default: throw Exception("unknown escape sequence");
        }
    }

    s.resize(d - s.begin());
    return s;
}

std::string hilti::rt::escapeUTF8(std::string_view s, bool escape_quotes, bool escape_control, bool keep_hex) {
    auto escapeControl = [escape_control](unsigned char c, const char* s) {
        return escape_control ? fmt(s) : std::string(1, c);
    };

    auto p = reinterpret_cast<const unsigned char*>(s.data());
    auto e = p + s.size();

    std::string esc;

    while ( p < e ) {
        utf8proc_int32_t cp;

        ssize_t n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 ) {
            esc += "<illegal UTF8 sequence>";
            break;
        }

        if ( cp == '\\' ) {
            if ( keep_hex && (p + n) < e && *(p + n) == 'x' )
                esc += "\\";
            else
                esc += "\\\\";
        }

        else if ( cp == '"' && escape_quotes )
            esc += "\\\"";

        else if ( *p == '\n' )
            esc += escapeControl(*p, "\\n");

        else if ( *p == '\r' )
            esc += escapeControl(*p, "\\r");

        else if ( *p == '\t' )
            esc += escapeControl(*p, "\\t");

        else {
            for ( ssize_t i = 0; i < n; i++ )
                esc += static_cast<char>(p[i]);
        }

        p += n;
    }

    return esc;
}

std::string hilti::rt::escapeBytes(std::string_view s, bool escape_quotes, bool use_octal) {
    auto p = s.data();
    auto e = p + s.size();

    std::string esc;

    while ( p < e ) {
        if ( *p == '\\' )
            esc += "\\\\";

        else if ( *p == '"' && escape_quotes )
            esc += "\\\"";

        else if ( isprint(*p) )
            esc += *p;

        else if ( use_octal )
            esc += fmt("\\%03o", static_cast<uint8_t>(*p));
        else
            esc += fmt("\\x%02x", static_cast<uint8_t>(*p));

        ++p;
    }

    return esc;
}

std::string hilti::rt::replace(std::string s, std::string_view o, std::string_view n) {
    if ( o.empty() )
        return s;

    size_t i = 0;
    while ( (i = s.find(o, i)) != std::string::npos ) {
        s.replace(i, o.length(), n);
        i += n.length();
    }

    return s;
}

hilti::rt::ByteOrder hilti::rt::systemByteOrder() {
#ifdef LITTLE_ENDIAN
    return ByteOrder::Little;
#elif BIG_ENDIAN
    return ByteOrder::Big;
#else
#error Neither LITTLE_ENDIAN nor BIG_ENDIAN defined.
#endif
}

std::string hilti::rt::strftime(const std::string& format, const hilti::rt::Time& time) {
    auto seconds = static_cast<time_t>(time.seconds());

    std::tm tm;

    constexpr size_t size = 128;
    char mbstr[size];

    auto localtime = ::localtime_r(&seconds, &tm);
    if ( ! localtime )
        throw InvalidArgument(hilti::rt::fmt("cannot convert timestamp to local time: %s", std::strerror(errno)));


    auto n = std::strftime(mbstr, size, format.c_str(), localtime);

    if ( ! n )
        throw InvalidArgument("could not format timestamp");

    return mbstr;
}
