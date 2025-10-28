// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <sys/resource.h>
#include <unistd.h>
#include <utf8proc/utf8proc.h>

#ifdef __linux__
#include <endian.h>
#endif

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include <hilti/rt/autogen/config.h>
#include <hilti/rt/autogen/version.h>
#include <hilti/rt/backtrace.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/fiber.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/global-state.h>
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

void hilti::rt::abort_with_backtrace() {
    fputs("\n--- Aborting in libhilti\n", stderr);
    auto bt = hilti::rt::Backtrace().backtrace();
    for ( const auto& f : *bt )
        std::cerr << f << '\n';
    abort();
}

void hilti::rt::cannot_be_reached() { hilti::rt::internalError("code is executing that should not be reachable"); }

hilti::rt::ResourceUsage hilti::rt::resource_usage() {
    ResourceUsage stats;

    struct rusage r;
    if ( getrusage(RUSAGE_SELF, &r) < 0 )
        throw EnvironmentError("cannot collect initial resource usage: %s", strerror(errno));

    auto fibers = detail::Fiber::statistics();

    const auto to_seconds = [](const timeval& t) {
        return static_cast<double>(t.tv_sec) + (static_cast<double>(t.tv_usec) / 1e6);
    };

    stats.user_time = to_seconds(r.ru_utime) - detail::globalState()->resource_usage_init.user_time;
    stats.system_time = to_seconds(r.ru_stime) - detail::globalState()->resource_usage_init.system_time;
    stats.memory_heap = r.ru_maxrss * 1024;
    stats.num_fibers = fibers.current;
    stats.max_fibers = fibers.max;
    stats.max_fiber_stack_size = fibers.max_stack_size;
    stats.cached_fibers = fibers.cached;

    return stats;
}

hilti::rt::Optional<std::string> hilti::rt::getenv(const std::string& name) {
    if ( auto* x = ::getenv(name.c_str()) )
        return {std::string(x)};
    else
        return {};
}

hilti::rt::Result<hilti::rt::filesystem::path> hilti::rt::createTemporaryFile(const std::string& prefix) {
    std::error_code ec;
    auto tmp_dir = hilti::rt::filesystem::temp_directory_path(ec);

    if ( ec )
        return hilti::rt::result::Error(fmt("could not create temporary file: %s", ec.message()));

    auto template_ = (tmp_dir / (prefix + "-XXXXXX")).native();

    auto handle = ::mkstemp(template_.data());
    if ( handle == -1 )
        return hilti::rt::result::Error(fmt("could not create temporary file in %s: %s", tmp_dir, strerror(errno)));

    ::close(handle);

    return hilti::rt::filesystem::path(template_);
}

hilti::rt::filesystem::path hilti::rt::normalizePath(const hilti::rt::filesystem::path& p) {
    if ( p.empty() )
        return "";

    if ( ! hilti::rt::filesystem::exists(p) )
        return p;

    return hilti::rt::filesystem::canonical(p);
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
        l.emplace_back("");

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
std::string hilti::rt::expandUTF8Escapes(std::string s) {
    auto d = s.begin();
    for ( auto c = d; c != s.end(); ) {
        if ( *c != '\\' ) {
            *d++ = *c++;
            continue;
        }

        ++c;

        if ( c == s.end() )
            throw RuntimeError("broken escape sequence");

        switch ( *c++ ) {
            case '\\': *d++ = '\\'; break;

            case '"': *d++ = '"'; break;

            case '0': *d++ = '\0'; break;

            case 'a': *d++ = '\a'; break;

            case 'b': *d++ = '\b'; break;

            case 'e': *d++ = '\e'; break;

            case 'f': *d++ = '\f'; break;

            case 'n': *d++ = '\n'; break;

            case 'r': *d++ = '\r'; break;

            case 't': *d++ = '\t'; break;

            case 'v': *d++ = '\v'; break;

            case 'u': {
                auto end = c + 4;
                if ( end > s.end() )
                    throw UnicodeError("incomplete unicode \\u");
                utf8proc_int32_t val = 0;
                c = atoi_n(c, end, 16, &val);

                if ( c != end )
                    throw UnicodeError("cannot decode character");

                uint8_t tmp[4];
                auto len = utf8proc_encode_char(val, tmp);

                if ( ! len )
                    throw UnicodeError("cannot encode unicode code point");

                d = std::copy(tmp, tmp + len, d);
                break;
            }

            case 'U': {
                auto end = c + 8;
                if ( end > s.end() )
                    throw UnicodeError("incomplete unicode \\U");
                utf8proc_int32_t val = 0;
                c = atoi_n(c, end, 16, &val);

                if ( c != end )
                    throw UnicodeError("cannot decode character");

                uint8_t tmp[4];
                auto len = utf8proc_encode_char(val, tmp);

                if ( ! len )
                    throw UnicodeError("cannot encode unicode code point");

                d = std::copy(tmp, tmp + len, d);
                break;
            }

            case 'x': {
                auto end = std::min(c + 2, s.end());
                if ( c == s.end() )
                    throw FormattingError("\\x used with no following hex digits");
                char val = 0;
                c = atoi_n(c, end, 16, &val);

                if ( c != end )
                    throw FormattingError("cannot decode character");

                *d++ = val;
                break;
            }

            default: throw FormattingError("unknown escape sequence");
        }
    }

    s.resize(d - s.begin());
    return s;
}

std::string hilti::rt::escapeUTF8(std::string_view s, bitmask<render_style::UTF8> style) {
    auto escapeControl = [style](auto c, const char* s) {
        return (style & render_style::UTF8::NoEscapeControl) ? std::string(1, c) : s;
    };

    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    const auto* e = p + s.size();

    std::string esc;

    while ( p < e ) {
        utf8proc_int32_t cp;

        ssize_t n = utf8proc_iterate(p, e - p, &cp);

        if ( n < 0 ) {
            esc += "<illegal UTF8 sequence>";
            break;
        }

        if ( cp == '\\' ) {
            if ( (style & render_style::UTF8::NoEscapeHex) && (p + n) < e && *(p + n) == 'x' )
                esc += "\\";
            else if ( ! (style & render_style::UTF8::NoEscapeBackslash) )
                esc += "\\\\";
            else
                esc += "\\";
        }

        else if ( cp == '"' && (style & render_style::UTF8::EscapeQuotes) )
            esc += "\\\"";

        else if ( *p == '\0' )
            esc += escapeControl(*p, "\\0");

        else if ( *p == '\a' )
            esc += escapeControl(*p, "\\a");

        else if ( *p == '\b' )
            esc += escapeControl(*p, "\\b");

        else if ( *p == '\e' )
            esc += escapeControl(*p, "\\e");

        else if ( *p == '\f' )
            esc += escapeControl(*p, "\\f");

        else if ( *p == '\n' )
            esc += escapeControl(*p, "\\n");

        else if ( *p == '\r' )
            esc += escapeControl(*p, "\\r");

        else if ( *p == '\t' )
            esc += escapeControl(*p, "\\t");

        else if ( *p == '\v' )
            esc += escapeControl(*p, "\\v");

        else {
            for ( ssize_t i = 0; i < n; i++ )
                esc += static_cast<char>(p[i]);
        }

        p += n;
    }

    return esc;
}

std::string hilti::rt::escapeBytes(std::string_view s, bitmask<render_style::Bytes> style) {
    const auto* p = s.data();
    const auto* e = p + s.size();

    std::string esc;

    while ( p < e ) {
        if ( *p == '\\' && ! (style & render_style::Bytes::NoEscapeBackslash) )
            esc += "\\\\";

        else if ( *p == '"' && (style & render_style::Bytes::EscapeQuotes) )
            esc += "\\\"";

        else if ( isprint(*p) )
            esc += *p;

        else if ( (style & render_style::Bytes::UseOctal) )
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

bool hilti::rt::startsWith(std::string_view s, std::string_view prefix) { return s.starts_with(prefix); }

bool hilti::rt::endsWith(std::string_view s, std::string_view suffix) {
    if ( s.size() < suffix.size() )
        return false;

    return s.substr(s.size() - suffix.size()) == suffix;
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

std::string hilti::rt::detail::adl::to_string(const hilti::rt::ByteOrder& x, tag /*unused*/) {
    switch ( x.value() ) {
        case hilti::rt::ByteOrder::Little: return "ByteOrder::Little";
        case hilti::rt::ByteOrder::Big: return "ByteOrder::Big";
        case hilti::rt::ByteOrder::Network: return "ByteOrder::Network";
        case hilti::rt::ByteOrder::Host: return "ByteOrder::Host";
        case hilti::rt::ByteOrder::Undef: return "ByteOrder::Undef";
    }

    cannot_be_reached();
}

std::string hilti::rt::strftime(const std::string& format, const hilti::rt::Time& time) {
    auto seconds = static_cast<time_t>(time.seconds());

    std::tm tm;

    constexpr size_t size = 128;
    char mbstr[size];

    // localtime() is required to call tzset() internally, whereas
    // localtime_r() may or may not do so -- to be portable we have to
    // call it ourselves:
    ::tzset();

    auto* localtime = ::localtime_r(&seconds, &tm);
    if ( ! localtime )
        throw InvalidArgument(hilti::rt::fmt("cannot convert timestamp to local time: %s", std::strerror(errno)));


    auto n = std::strftime(mbstr, size, format.c_str(), localtime);

    if ( ! n )
        throw InvalidArgument("could not format timestamp");

    return mbstr;
}

hilti::rt::Time hilti::rt::strptime(const std::string& buf, const std::string& format) {
    tm time;
    const char* end = ::strptime(buf.data(), format.c_str(), &time);

    if ( ! end )
        throw InvalidArgument("could not parse time string");

    auto consumed = std::distance(buf.data(), end);
    if ( static_cast<decltype(buf.size())>(consumed) != buf.size() )
        throw InvalidArgument(hilti::rt::fmt("unparsed remainder after parsing time string: %s", end));

    // If the struct tm object was obtained from POSIX strptime or equivalent
    // function, the value of tm_isdst is indeterminate, and needs to be set explicitly
    // before calling mktime, see https://en.cppreference.com/w/c/chrono/mktime.
    time.tm_isdst = -1;

    auto secs = ::mktime(&time);
    if ( secs == -1 )
        throw OutOfRange(hilti::rt::fmt("value cannot be represented as a time: %s", std::strerror(errno)));

    return hilti::rt::Time(static_cast<double>(secs), hilti::rt::Time::SecondTag{});
}
