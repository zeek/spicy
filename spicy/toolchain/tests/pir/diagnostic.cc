// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <string_view>

#include <spicy/compiler/detail/pir/ir/builder.h>
#include <spicy/compiler/detail/pir/ir/diagnostic.h>
#include <spicy/compiler/detail/pir/ir/internal-error.h>
#include <spicy/compiler/detail/pir/ir/package.h>

using namespace spicy::detail::pir::ir;

TEST_SUITE("pir::ir::Diagnostic") {
    TEST_CASE("every user catalog definition has a short, unique, kebab-case ID") {
        static constexpr const DiagnosticDefinition* all[] = {
            &diag::UnusedField,
            &diag::FieldReadBeforeParsed,
            &diag::FieldParsedHere,
        };

        for ( const auto* def : all ) {
            std::string_view id = def->id;
            CHECK_FALSE(id.empty());
            CHECK_FALSE(id.starts_with("PIR_"));
            CHECK(id.find_first_not_of("abcdefghijklmnopqrstuvwxyz-") == std::string_view::npos);
            CHECK(std::string_view(def->message).size() > 0);
        }

        // Each diagnostic needs a unique ID.
        for ( size_t i = 0; i < std::size(all); ++i )
            for ( size_t j = i + 1; j < std::size(all); ++j )
                CHECK(*all[i] != *all[j]);
    }

    TEST_CASE("emit() keeps the definition and formats its message") {
        Package package;
        auto builder = package.builder();
        auto unit = builder.createUnitDecl("Item");
        auto field = builder.createFieldDecl(unit, "x", builder.uint8Type());

        std::vector<Diagnostic> sink;
        DiagnosticEmitter emitter(package, sink);
        emitter.emit(diag::UnusedField, field, "Item::x");

        REQUIRE(sink.size() == 1);
        CHECK(sink[0].definition == diag::UnusedField);
        CHECK(sink[0].message == "field 'Item::x' is parsed but never used; consider making it 'skip'");
        CHECK(std::holds_alternative<DeclId>(sink[0].primary.entity));
    }
}

TEST_SUITE("pir::ir::InternalError") {
    TEST_CASE("emit() formats the message and keeps the tag") {
        Package package;
        std::vector<InternalError> sink;
        InternalErrorEmitter emitter(package, sink);

        emitter.emit("operand-count-mismatch", "expected %d operand(s), got %d", InstId{2}, size_t{1}, size_t{3});

        REQUIRE(sink.size() == 1);
        CHECK(sink[0].tag == "operand-count-mismatch");
        CHECK(sink[0].message == "expected 1 operand(s), got 3");
        CHECK(std::holds_alternative<InstId>(sink[0].site.entity));
    }

    TEST_CASE("emit() from an InstId automatically retains that instruction's stored span") {
        Package package;
        auto builder = package.builder();
        auto file = package.sourceManager().internFile("x.spicy");
        auto span = package.sourceManager().addSpan(SourceSpan{.file = file, .begin_line = 9, .begin_column = 2});

        auto fn = builder.createFunction("f", builder.int64Type());
        auto block = builder.createBlock(package.function(fn).root_region);
        auto c = builder.addConstant(block, 1, span);

        std::vector<InternalError> errors;
        InternalErrorEmitter emitter(package, errors);
        emitter.emit("unrecognized-opcode", "unrecognized opcode", c);

        REQUIRE(errors.size() == 1);
        CHECK(errors[0].site.source == span);
        CHECK(std::holds_alternative<InstId>(errors[0].site.entity));
    }

    TEST_CASE(".note() from a FunctionId automatically retains that function's stored span") {
        Package package;
        auto builder = package.builder();
        auto file = package.sourceManager().internFile("x.spicy");
        auto span = package.sourceManager().addSpan(SourceSpan{.file = file, .begin_line = 3, .begin_column = 17});

        auto fn = builder.createFunction("answer", builder.int64Type(), span);

        std::vector<InternalError> errors;
        InternalErrorEmitter emitter(package, errors);
        emitter.emit("return-type-mismatch", "returned value has type %s, expected %s", noSite(), "int64", "void")
            .note("function-declared-here", "function declared with result type %s", fn, "void");

        REQUIRE(errors.size() == 1);
        REQUIRE(errors[0].notes.size() == 1);
        CHECK(errors[0].notes[0].site.source == span);
        CHECK(std::holds_alternative<FunctionId>(errors[0].notes[0].site.entity));
    }

    TEST_CASE("rendering is entity-first, with source location as secondary provenance") {
        Package package;
        auto builder = package.builder();
        auto file = package.sourceManager().internFile("test.spicy");
        auto return_span = package.sourceManager().addSpan(
            SourceSpan{.file = file, .begin_line = 4, .begin_column = 12, .end_line = 4, .end_column = 20});
        auto fn_span = package.sourceManager().addSpan(
            SourceSpan{.file = file, .begin_line = 3, .begin_column = 17, .end_line = 3, .end_column = 30});

        auto fn = builder.createFunction("answer", builder.int64Type(), fn_span);
        auto block = builder.createBlock(package.function(fn).root_region);
        auto c = builder.addConstant(block, 1);
        auto ret = builder.addInstForTesting(block, Opcode::Return, {c}, builder.voidType(), {}, return_span);

        std::vector<InternalError> errors;
        InternalErrorEmitter emitter(package, errors);
        emitter.emit("return-type-mismatch", "returned value has type %s, expected %s", ret, "int64", "void")
            .note("function-declared-here", "function declared with result type %s", fn, "void");

        auto out = render(package, errors);
        CHECK(out ==
              "internal compiler error[return-type-mismatch]\n"
              "  at instruction %1 (core.return)\n"
              "  source origin: test.spicy:4:12\n"
              "  detail: returned value has type int64, expected void\n"
              "internal compiler note[function-declared-here]\n"
              "  at function %0 \"answer\"\n"
              "  source origin: test.spicy:3:17\n"
              "  detail: function declared with result type void\n");
    }

    TEST_CASE("rendering a malformed entity or span reference does not assert") {
        Package package;

        std::vector<InternalError> errors;
        InternalErrorEmitter emitter(package, errors);
        emitter.emit("invalid-operand-id",
                     "operand %d references an invalid instruction ID",
                     DiagnosticSite{.source = SourceSpanId{7}, .entity = InstId{42}},
                     size_t{0});
        emitter.emit("orphan-regions",
                     "%d region(s) are not owned by any function or instruction",
                     noSite(),
                     size_t{1});

        auto out = render(package, errors);
        CHECK(out.find("<invalid-span>") != std::string::npos);
        CHECK(out.find("instruction %42") != std::string::npos);
        // No entity or source span means neither location line is printed.
        auto orphan_pos = out.find("orphan-regions");
        REQUIRE(orphan_pos != std::string::npos);
        CHECK(out.find("  at ", orphan_pos) == std::string::npos);
        CHECK(out.find("  source origin", orphan_pos) == std::string::npos);
    }
}
