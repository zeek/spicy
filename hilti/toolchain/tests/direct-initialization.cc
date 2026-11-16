// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

// Direct initialization is an internal AST option with no HILTI source syntax.
#include <doctest/doctest.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <sstream>
#include <string>

#include <hilti/rt/init.h>

#include <hilti/ast/builder/builder.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/driver.h>
#include <hilti/compiler/init.h>
#include <hilti/hilti.h>

using namespace hilti;

namespace {

bool compileRecord(bool direct,
                   bool omit,
                   bool with_default,
                   bool optimize,
                   const std::string& expected_error,
                   bool read_payload = true) {
    // Operator registration belongs to the first AST context in a process; isolate each compilation.
    auto pid = fork();
    REQUIRE(pid >= 0);
    if ( pid == 0 ) {
        hilti::init();
        std::stringstream log;
        Driver driver("hilti-direct-initialization-test", util::currentExecutable());
        driver::Options options;
        options.logger = std::make_unique<Logger>(log, log);
        options.execute_code = expected_error.empty();
        options.include_linker = true;
        driver.setDriverOptions(std::move(options));
        auto compiler_options = driver.hiltiOptions();
        compiler_options.global_optimizations = optimize;
        driver.setCompilerOptions(compiler_options);
        if ( ! driver.initialize() )
            _exit(2);

        auto* b = driver.builder();
        auto* integer = b->qualifiedType(b->typeSignedInteger(64), Constness::Mutable);
        auto* string = b->qualifiedType(b->typeString(), Constness::Mutable);
        auto* attrs = b->attributeSet();
        if ( with_default )
            attrs->add(b->context(), b->attribute(attribute::kind::Default, b->integer(9)));
        auto* record = b->typeStruct({
            b->declarationField(ID("value"), integer, attrs),
            b->declarationField(ID("payload"),
                                b->qualifiedType(b->typeOptional(string), Constness::Mutable),
                                b->attributeSet()),
        });
        if ( direct )
            record->setUsesDirectFieldInitialization();
        auto* type = b->qualifiedType(record, Constness::Mutable);
        auto* decl = b->declarationType(ID("Record"), type);
        auto* named_type = b->qualifiedType(b->typeName(ID("Record")), Constness::Mutable);
        auto* body = b->statementBlock();
        ExtendedBuilderTemplate<Builder> init(b->context(), body);
        ctor::struct_::Fields fields = {b->ctorStructField(ID("value"), b->integer(7))};
        if ( ! omit )
            fields.push_back(b->ctorStructField(ID("payload"), b->stringLiteral("present")));
        if ( omit )
            init.addExpression(b->struct_(fields, type));
        else {
            init.addLocal(ID("populated"), named_type, b->struct_(fields));
            init.addAssert(init.equal(init.member(init.id("populated"), "value"), init.integer(7)), "integer value");
            if ( read_payload )
                init.addAssert(init.equal(init.deref(init.member(init.id("populated"), "payload")),
                                          init.stringLiteral("present")),
                               "optional payload");
            init.addLocal(ID("empty"),
                          named_type,
                          b->struct_({b->ctorStructField(ID("value"), b->integer(8)),
                                      b->ctorStructField(ID("payload"), b->null())}));
            if ( read_payload ) {
                auto unexpected = init.addIf(init.member(init.id("empty"), "payload"));
                unexpected->addAssert(unexpected->bool_(false), "explicitly empty optional");
            }
            init.addAssert(init.equal(init.member(init.id("empty"), "value"), init.integer(8)), "second value");
        }
        auto* module = b->declarationModule(declaration::module::UID(ID("Test"), ".hlt", ".hlt"), {}, {decl}, {body});
        b->context()->addModule(module);
        auto added = driver.addInput(module->uid());
        bool ok = added && driver.compile();
        if ( ok && expected_error.empty() ) {
            try {
                hilti::rt::init();
            } catch ( const std::exception& e ) {
                log << e.what();
                ok = false;
            }
        }
        bool matched = expected_error.empty() ? ok : ! ok && log.str().find(expected_error) != std::string::npos;
        if ( ! matched )
            std::fprintf(stderr, "%s", log.str().c_str());
        _exit(matched ? 0 : 1);
    }
    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

} // namespace

TEST_SUITE("Direct struct initialization") {
    TEST_CASE("explicit empty and populated optionals retain their values") {
        for ( bool optimize : {false, true} ) {
            CAPTURE(optimize);
            CHECK(compileRecord(true, false, false, optimize, ""));
        }
    }

    TEST_CASE("fields the optimizer removes need no initializer") {
        CHECK(compileRecord(true, false, false, true, "", false));
    }

    TEST_CASE("direct records reject omitted initializers") {
        CHECK(compileRecord(true, true, false, true, "requires an initializer for field 'payload'"));
    }

    TEST_CASE("field defaults require the general constructor") {
        CHECK(compileRecord(true, false, true, true, "requires ordinary fields"));
        CHECK(compileRecord(false, false, true, true, ""));
    }
}
