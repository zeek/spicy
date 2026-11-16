// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

using namespace hilti;

namespace {

bool compileLocations(bool explicit_locations, bool track) {
    auto pid = fork();
    REQUIRE(pid >= 0);
    if ( pid == 0 ) {
        hilti::init();
        auto directory = hilti::rt::filesystem::temp_directory_path() / util::fmt("hilti-location-test-%d", getpid());
        hilti::rt::filesystem::create_directory(directory);
        std::stringstream log;
        Driver driver("hilti-location-test", util::currentExecutable());
        driver::Options options;
        options.logger = std::make_unique<Logger>(log, log);
        options.output_cxx = true;
        options.output_cxx_prefix = (directory / "parser").string();
        driver.setDriverOptions(std::move(options));
        auto compiler_options = driver.hiltiOptions();
        compiler_options.global_optimizations = false;
        compiler_options.track_location = track;
        compiler_options.debug_trace = true;
        driver.setCompilerOptions(compiler_options);
        if ( ! driver.initialize() )
            _exit(2);

        auto* b = driver.builder();
        auto meta = Meta(Location("implicit-site", 10));
        auto* body = b->statementBlock(meta);
        ExtendedBuilderTemplate<Builder> fb(b->context(), body);
        body->_add(b->context(), b->statementSetLocation(b->stringLiteral("explicit-site")));
        fb.addReturn(fb.integer(7), meta);
        auto* function = b->function(ID("f"),
                                     b->qualifiedType(b->typeSignedInteger(64), Constness::Mutable),
                                     {},
                                     body,
                                     type::function::Flavor::Function,
                                     declaration::Linkage::Public);
        if ( explicit_locations )
            function->function()->setUsesExplicitLocationTracking();
        auto* module = b->declarationModule(declaration::module::UID(ID("Test"), ".hlt", ".hlt"), {}, {function});
        b->context()->addModule(module);
        auto added = driver.addInput(module->uid());
        bool ok = added && driver.compile();
        std::string code;
        for ( const auto& file : hilti::rt::filesystem::directory_iterator(directory) ) {
            std::ifstream input(file.path());
            std::stringstream text;
            text << input.rdbuf();
            code += text.str();
        }
        auto contains = [&](const std::string& text) { return code.find(text) != std::string::npos; };
        ok = ok && contains("::hilti::rt::location(\"implicit-site:10\")") == (track && ! explicit_locations) &&
             contains("::hilti::rt::location(\"explicit-site\")") &&
             contains("HILTI_RT_DEBUG(\"hilti-trace\", \"implicit-site:10");
        if ( ! ok )
            std::fprintf(stderr, "%s\n%s", log.str().c_str(), code.c_str());
        hilti::rt::filesystem::remove_all(directory);
        _exit(ok ? 0 : 1);
    }
    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

} // namespace

TEST_SUITE("Location tracking") {
    TEST_CASE("explicit tracking keeps debug metadata and explicit updates") {
        for ( bool track : {false, true} ) {
            CAPTURE(track);
            CHECK(compileLocations(true, track));
        }
    }
    TEST_CASE("ordinary functions retain automatic and explicit location behavior") {
        for ( bool track : {false, true} ) {
            CAPTURE(track);
            CHECK(compileLocations(false, track));
        }
    }
}
