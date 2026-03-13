// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#ifdef _WIN32
#include <stdlib.h>
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif

#include <doctest/doctest.h>

#include <cstdlib>
#include <fstream>
#include <ostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <hilti/rt/autogen/tests/config.h>
#include <hilti/rt/filesystem.h>
#include <hilti/rt/library.h>
#include <hilti/rt/test/utils.h>
#include <hilti/rt/util.h>

// // Since this file is ATM generated at configure time we do not need to add a dependency on `hilti`.
// #include <hilti/autogen/config.h>

using namespace hilti::rt;
using namespace hilti::rt::test;

namespace {

// Returns true if the process is running with elevated privileges
// (root on Unix, administrator on Windows).
bool is_elevated_user() {
#ifdef _WIN32
    HANDLE token = NULL;
    if ( ! OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) )
        return false;

    TOKEN_ELEVATION elevation;
    DWORD size;
    BOOL result = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);

    return result && elevation.TokenIsElevated;
#else
    return geteuid() == 0;
#endif
}

} // namespace

const hilti::rt::filesystem::path dummy1 =
    config::lib_directory /
    (config::shared_library_prefix + "hilti-rt-tests-library-dummy1" + config::shared_library_suffix);

const hilti::rt::filesystem::path dummy2 =
    config::lib_directory /
    (config::shared_library_prefix + "hilti-rt-tests-library-dummy2" + config::shared_library_suffix);

// RAII helper to set an environment variable.
class Env {
public:
    Env(std::string k, const std::string_view& v) {
        if ( auto* prev = ::getenv(k.data()) )
            _prev = {k, prev};
        else
            _prev = {k, std::nullopt};

#ifdef _WIN32
        REQUIRE_EQ(::_putenv_s(k.c_str(), v.data()), 0);
#else
        REQUIRE_EQ(::setenv(k.c_str(), v.data(), 1), 0);
#endif
    }

    ~Env() {
        const auto& k = _prev.first;
        const auto& v = _prev.second;

        if ( v ) {
#ifdef _WIN32
            REQUIRE_EQ(::_putenv_s(k.c_str(), v->c_str()), 0);
#else
            REQUIRE_EQ(::setenv(k.c_str(), v->c_str(), 1), 0);
#endif
        }
        else {
#ifdef _WIN32
            REQUIRE_EQ(::_putenv_s(k.c_str(), ""), 0);
#else
            REQUIRE_EQ(::unsetenv(k.c_str()), 0);
#endif
        }
    }

private:
    std::pair<std::string, std::optional<std::string>> _prev;
};

TEST_SUITE_BEGIN("Library");

TEST_CASE("construct" * doctest::skip(is_elevated_user())) {
    Library _(dummy1); // Does not throw
    CHECK_THROWS_AS(Library(hilti::rt::filesystem::path("does") / "not" / "exist"), std::runtime_error);
}

TEST_CASE("open") {
    SUBCASE("success") {
        {
            // Creating `Library` instance does not load it automatically.
            Library library(dummy1);
            CHECK_FALSE(library.symbol("foo").hasValue());

            // Explicitly opening the `Library` loads it so the symbol can be found.
            REQUIRE(library.open());
            auto symbol = library.symbol("foo");
            REQUIRE(symbol.hasValue());
            CHECK(symbol.value());
        }
    }

    SUBCASE("invalid library") {
        // Create a temporary file that is not a valid shared library.
        hilti::rt::TemporaryDirectory tmp;
        auto invalid = tmp.path() / "not_a_library.txt";
        {
            std::ofstream(invalid) << "not a library";
        }

        Library library(invalid);
        const auto open = library.open();
        REQUIRE_FALSE(open);
        CHECK_NE(open.error().description().find("failed to load library"), std::string::npos);
    }
}

// NOTE: The 2nd subcase likely does not work if run as `root`/`admin` as they
// can probably create files even in read-only directories.
TEST_CASE("save" * doctest::skip(is_elevated_user())) {
    Library library(dummy1);

    SUBCASE("success") {
        hilti::rt::TemporaryDirectory tmp;
        Env _("TMPDIR", tmp.path().string().c_str());
        CHECK_EQ(library.save(tmp.path()), Nothing());

        SUBCASE("overwrite existing") { CHECK_EQ(library.save(tmp.path()), Nothing()); }
    }

#ifndef _WIN32
    // POSIX directory permissions don't prevent file creation on Windows,
    // so this subcase only works on Unix-like systems.
    SUBCASE("target not writable") {
        TemporaryDirectory tmp;
        Env _("TMPDIR", tmp.path().c_str());
        hilti::rt::filesystem::permissions(tmp.path(), hilti::rt::filesystem::perms::none);

        const auto save = library.save(tmp.path() / ("library" + config::shared_library_suffix));
        REQUIRE_FALSE(save);
        // Cannot check exact error text as it depends on e.g., the system locale.
        CHECK_FALSE(save.error().description().empty());
    }
#endif
}

TEST_CASE("symbol") {
    auto call = [](void* sym) {
        using foo_t = int();
        return (*reinterpret_cast<foo_t*>(sym))();
    };

    const Library library1(dummy1);
    {
        auto sym = library1.symbol("foo");
        REQUIRE_FALSE(sym);
        CHECK_MESSAGE(sym.error().description().rfind("has not been opened") != std::string::npos, sym.error());
    }

    REQUIRE(library1.open());

    CHECK_EQ(library1.symbol("bar"), result::Error("symbol 'bar' not found"));

    const auto foo1 = library1.symbol("foo");
    REQUIRE(foo1);
    CHECK_EQ(call(*foo1), 1);

    // We can load a similarly named symbol from another library.
    const Library library2(dummy2);
    REQUIRE(library2.open());

    const auto foo2 = library2.symbol("foo");
    REQUIRE_NE(foo1, foo2);
    REQUIRE(foo2);
    CHECK_EQ(call(*foo2), 2);
}

TEST_CASE("json") {
    const Library library(dummy1);
    const auto open = library.open();
    REQUIRE(open);

    const auto& version1 = open.value();
    auto version2 = library::Version::fromJSON(version1.toJSON());
    REQUIRE(version2);
    CHECK_EQ(version1, version2);
}

TEST_SUITE_END();
