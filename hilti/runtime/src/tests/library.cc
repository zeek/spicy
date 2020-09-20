// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <dlfcn.h>
#include <unistd.h>

#include <cstdlib>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <hilti/rt/autogen/tests/config.h>
#include <hilti/rt/doctest.h>
#include <hilti/rt/filesystem.h>
#include <hilti/rt/library.h>
#include <hilti/rt/test/utils.h>
#include <hilti/rt/util.h>

// // Since this file is ATM generated at configure time we do not need to add a dependency on `hilti`.
// #include <hilti/autogen/config.h>

using namespace hilti::rt;
using namespace hilti::rt::test;

const std::filesystem::path dummy1 =
    config::lib_directory / ("libhilti-rt-tests-library-dummy1" + config::shared_library_suffix);

const std::filesystem::path dummy2 =
    config::lib_directory / ("libhilti-rt-tests-library-dummy2" + config::shared_library_suffix);

// Helper function check whether a symbol could be resolved in the current process image.
bool has_symbol(const char* sym) { return ::dlsym(RTLD_DEFAULT, "foo"); };

// RAII helper to set an environment variable.
class Env {
public:
    Env(std::string k, const std::string_view& v) {
        if ( auto prev = ::getenv(k.data()) )
            _prev = {k, prev};
        else
            _prev = {k, std::nullopt};

        REQUIRE_EQ(::setenv(k.c_str(), v.data(), 1), 0);
    }

    ~Env() {
        const auto& [k, v] = _prev;

        if ( v )
            REQUIRE_EQ(::setenv(k.c_str(), v->c_str(), 1), 0);
        else
            REQUIRE_EQ(::unsetenv(k.c_str()), 0);
    }

private:
    std::pair<std::string, std::optional<std::string>> _prev;
};

// RAII helper to create a temporary directory.
class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto tmpdir = std::filesystem::temp_directory_path();
        auto template_ = (tmpdir / "hilti-rt-test-XXXXXX").native();
        auto path = ::mkdtemp(template_.data());
        REQUIRE_NE(path, nullptr);
        _path = path;
    }

    ~TemporaryDirectory() {
        if ( ! std::filesystem::exists(_path) )
            return;

        // Make sure we have permissions to remove the directory.
        std::filesystem::permissions(_path, std::filesystem::perms::all);
        for ( const auto& entry : std::filesystem::recursive_directory_iterator(_path) )
            std::filesystem::permissions(entry, std::filesystem::perms::all);

        std::filesystem::remove_all(_path);
    }

    const auto& path() const { return _path; }

private:
    std::filesystem::path _path;
};

TEST_SUITE_BEGIN("Library");

TEST_CASE("construct") {
    Library _(dummy1); // Does not throw
    CHECK_THROWS_WITH_AS(Library("/does/not/exist"), "no such library: \"/does/not/exist\"", const EnvironmentError&);

    SUBCASE("TMPDIR does not exist") {
        Env _("TMPDIR", "/does/not/exist");
        try {
            Library _(dummy1);
            FAIL("expected exception not thrown");
        } catch ( const EnvironmentError& e ) {
            CAPTURE(e.description());
            CHECK(startsWith(e.description(),
                             fmt("could not add library \"%s\": could not create temporary file: ", dummy1.c_str())));
        } catch ( ... ) {
            FAIL("unexpected exception thrown");
        }
    }

    SUBCASE("cannot write TMPDIR") {
        // NOTE: This test likely does not work if run as `root` as `root`
        // can probably create files even in read-only directories.
        TemporaryDirectory tmpdir;
        std::filesystem::permissions(tmpdir.path(), std::filesystem::perms::none);
        Env _("TMPDIR", tmpdir.path().c_str());

        try {
            Library _(dummy1);
            FAIL("expected exception not thrown");
        } catch ( const EnvironmentError& e ) {
            CAPTURE(e.description());
            CHECK(startsWith(e.description(),
                             fmt("could not add library \"%s\": could not create temporary file in ", dummy1.c_str())));
        } catch ( ... ) {
            FAIL("unexpected exception thrown");
        }
    }
}

TEST_CASE("destruct") {
    TemporaryDirectory tmp;
    Env _("TMPDIR", tmp.path().c_str());

    auto library = std::unique_ptr<Library>(new Library(dummy1));

    // Recursively change the permissions of the directory
    // so the temporary library cannot be removed anymore.
    //
    // NOTE: This test likely does not work if run as `root` as `root`
    // can probably create files even in read-only directories.
    for ( const auto& entry : std::filesystem::recursive_directory_iterator(tmp.path()) )
        std::filesystem::permissions(entry, std::filesystem::perms::none);
    std::filesystem::permissions(tmp.path(), std::filesystem::perms::none);

    CaptureIO cerr(std::cerr);

    CHECK_NOTHROW(library.reset());
    CHECK_NE(cerr.str().find("could not remove library"), std::string::npos);
}

TEST_CASE("open") {
    SUBCASE("success") { // Symbol not loaded, yet.
        REQUIRE_FALSE(has_symbol("foo"));

        {
            // Creating `Library` instance does not load it automatically.
            Library library(dummy1);
            CHECK_FALSE(has_symbol("foo"));

            // Explicitly opening the `Library` loads it so the symbol can be found.
            REQUIRE(library.open());
            CHECK(has_symbol("foo"));
        }

        // The library is not closed when its `Library` goes out of scope.
        CHECK(has_symbol("foo"));
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

TEST_CASE("save") {
    Library library(dummy1);

    SUBCASE("success") {
        TemporaryDirectory tmp;
        Env _("TMPDIR", tmp.path().c_str());
        CHECK_EQ(library.save(tmp.path()), Nothing());

        SUBCASE("overwrite existing") { CHECK_EQ(library.save(tmp.path()), Nothing()); }
    }

    SUBCASE("target not writable") {
        // NOTE: This test likely does not work if run as `root` as `root`
        // can probably create files even in read-only directories.
        TemporaryDirectory tmp;
        Env _("TMPDIR", tmp.path().c_str());
        std::filesystem::permissions(tmp.path(), std::filesystem::perms::none);

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
