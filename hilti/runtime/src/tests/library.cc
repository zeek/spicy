// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>
#include <doctest/doctest.h>
#include <unistd.h>

#include <cstdlib>
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

const hilti::rt::filesystem::path dummy1 =
    config::lib_directory / ("libhilti-rt-tests-library-dummy1" + config::shared_library_suffix);

const hilti::rt::filesystem::path dummy2 =
    config::lib_directory / ("libhilti-rt-tests-library-dummy2" + config::shared_library_suffix);

// RAII helper to set an environment variable.
class Env {
public:
    Env(std::string k, const std::string_view& v) {
        if ( auto* prev = ::getenv(k.data()) )
            _prev = {k, prev};
        else
            _prev = {k, std::nullopt};

        REQUIRE_EQ(::setenv(k.c_str(), v.data(), 1), 0);
    }

    ~Env() {
        const auto& k = _prev.first;
        const auto& v = _prev.second;

        if ( v ) {
            REQUIRE_EQ(::setenv(k.c_str(), v->c_str(), 1), 0);
        }
        else {
            REQUIRE_EQ(::unsetenv(k.c_str()), 0);
        }
    }

private:
    std::pair<std::string, std::optional<std::string>> _prev;
};

TEST_SUITE_BEGIN("Library");

TEST_CASE("construct" * doctest::skip(geteuid() == 0)) {
    Library _(dummy1); // Does not throw
    CHECK_THROWS_AS(Library("/does/not/exist"), std::runtime_error);
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
        // We pick a regular, non-block library file which is not
        // a library and should be present on most systems here.
        Library library("/etc/group");
        const auto open = library.open();
        REQUIRE_FALSE(open);
        CHECK_NE(open.error().description().find("failed to load library"), std::string::npos);
    }
}

// NOTE: The 2nd subcase likely does not work if run as `root` as `root`
// can probably create files even in read-only directories.
TEST_CASE("save" * doctest::skip(geteuid() == 0)) {
    Library library(dummy1);

    SUBCASE("success") {
        hilti::rt::TemporaryDirectory tmp;
        Env _("TMPDIR", tmp.path().c_str());
        CHECK_EQ(library.save(tmp.path()), Nothing());

        SUBCASE("overwrite existing") { CHECK_EQ(library.save(tmp.path()), Nothing()); }
    }

    SUBCASE("target not writable") {
        TemporaryDirectory tmp;
        Env _("TMPDIR", tmp.path().c_str());
        hilti::rt::filesystem::permissions(tmp.path(), hilti::rt::filesystem::perms::none);

        const auto save = library.save(tmp.path() / ("library" + config::shared_library_suffix));
        REQUIRE_FALSE(save);
        // Cannot check exact error text as it depends on e.g., the system locale.
        CHECK_FALSE(save.error().description().empty());
    }
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
