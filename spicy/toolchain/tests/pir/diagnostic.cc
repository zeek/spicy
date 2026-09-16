// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <spicy/compiler/detail/pir/ir/diagnostic.h>
#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>

using namespace spicy::detail::pir::ir;

namespace {

Diagnostic emitOne(const Package& package,
                   std::vector<Diagnostic>& sink,
                   const DiagnosticDefinition& def,
                   InstId id,
                   int a,
                   int b) {
    DiagnosticEmitter emitter(package, sink);
    emitter.emit(def, id, a, b);
    return sink.back();
}

} // namespace

TEST_SUITE("pir::ir::Diagnostic") {
    TEST_CASE("every catalog definition has an Internal classification and a non-empty, stable ID") {
        static constexpr const DiagnosticDefinition* all[] = {
            &diag::InvalidFunctionResultType,
            &diag::InvalidRootRegion,
            &diag::RegionBlockCountMismatch,
            &diag::InvalidBlockId,
            &diag::EmptyBlock,
            &diag::InvalidInstructionId,
            &diag::CachedParentMismatch,
            &diag::UnrecognizedOpcode,
            &diag::TerminatorNotLast,
            &diag::MissingTerminator,
            &diag::OperandCountMismatch,
            &diag::UnexpectedPayload,
            &diag::MissingPayload,
            &diag::InvalidOperandId,
            &diag::OperandNotSameBlock,
            &diag::OperandUsedBeforeDefinition,
            &diag::VoidOperandUsed,
            &diag::OperandTypeMismatch,
            &diag::ResultTypeMismatch,
            &diag::ReturnTypeMismatch,
            &diag::DuplicateRegionOwnership,
            &diag::DuplicateBlockOwnership,
            &diag::DuplicateInstructionOwnership,
            &diag::OrphanRegions,
            &diag::OrphanBlocks,
            &diag::OrphanInstructions,
            &diag::InvalidSourceSpanId,
            &diag::InvalidSourceFileId,
            &diag::MalformedSourceSpanRange,
            &diag::FunctionDeclaredHere,
            &diag::OperandDefinedHere,
        };

        for ( const auto* def : all ) {
            CHECK(std::string_view(def->id).starts_with("PIR_"));
            CHECK(std::string_view(def->message).size() > 0);
            CHECK(def->classification == DiagnosticClassification::Internal);
        }

        // IDs are the sole identity of a definition now that there is no separate code enum;
        // every one must be unique.
        for ( size_t i = 0; i < std::size(all); ++i )
            for ( size_t j = i + 1; j < std::size(all); ++j )
                CHECK(*all[i] != *all[j]);
    }

    TEST_CASE("emit() formats through the catalog definition without explicit template arguments") {
        Package package;
        std::vector<Diagnostic> sink;
        DiagnosticEmitter emitter(package, sink);

        emitter.emit(diag::OperandCountMismatch, InstId{2}, size_t{1}, size_t{3});

        REQUIRE(sink.size() == 1);
        CHECK(sink[0].definition == diag::OperandCountMismatch);
        CHECK(sink[0].message == "expected 1 operand(s), got 3");
        CHECK(std::holds_alternative<InstId>(sink[0].primary.entity));
    }

    TEST_CASE("repeated emissions of one condition share a definition but format different arguments") {
        Package package;
        std::vector<Diagnostic> sink;
        auto first = emitOne(package, sink, diag::OperandCountMismatch, InstId{0}, 1, 2);
        auto second = emitOne(package, sink, diag::OperandCountMismatch, InstId{1}, 3, 4);

        CHECK(first.definition == second.definition);
        CHECK(first.message != second.message);
    }

    TEST_CASE("runtime diagnostics retain the exact definition passed to emit(), without a reverse lookup") {
        Package package;
        std::vector<Diagnostic> sink;
        DiagnosticEmitter emitter(package, sink);

        emitter.emit(diag::UnrecognizedOpcode, noSite());

        REQUIRE(sink.size() == 1);
        // Stored by value, so this checks for the exact same definition rather than a re-derived
        // copy: same stable ID, same classification, same severity, same message template.
        CHECK(sink[0].definition == diag::UnrecognizedOpcode);
        CHECK(sink[0].definition.id == diag::UnrecognizedOpcode.id);
        CHECK(sink[0].definition.classification == diag::UnrecognizedOpcode.classification);
    }

    TEST_CASE("emit() from an InstId automatically retains that instruction's stored span") {
        Package package;
        auto file = package.sourceManager().internFile("x.spicy");
        auto span = package.sourceManager().addSpan(SourceSpan{.file = file, .begin_line = 9, .begin_column = 2});

        auto fn = package.createFunction("f", package.int64Type());
        auto block = package.createBlock(package.function(fn).root_region);
        auto c = package.addConstant(block, 1, span);

        std::vector<Diagnostic> diags;
        DiagnosticEmitter emitter(package, diags);
        emitter.emit(diag::UnrecognizedOpcode, c);

        REQUIRE(diags.size() == 1);
        CHECK(diags[0].primary.source == span);
        CHECK(std::holds_alternative<InstId>(diags[0].primary.entity));
    }

    TEST_CASE(".note() from a FunctionId automatically retains that function's stored span") {
        Package package;
        auto file = package.sourceManager().internFile("x.spicy");
        auto span = package.sourceManager().addSpan(SourceSpan{.file = file, .begin_line = 3, .begin_column = 17});

        auto fn = package.createFunction("answer", package.int64Type(), span);

        std::vector<Diagnostic> diags;
        DiagnosticEmitter emitter(package, diags);
        emitter.emit(diag::ReturnTypeMismatch, noSite(), "int64", "void").note(diag::FunctionDeclaredHere, fn, "void");

        REQUIRE(diags.size() == 1);
        REQUIRE(diags[0].notes.size() == 1);
        CHECK(diags[0].notes[0].site.source == span);
        CHECK(std::holds_alternative<FunctionId>(diags[0].notes[0].site.entity));
    }

    TEST_CASE("ICE rendering is entity-first, with source location as secondary provenance") {
        Package package;
        auto file = package.sourceManager().internFile("test.spicy");
        auto return_span = package.sourceManager().addSpan(
            SourceSpan{.file = file, .begin_line = 4, .begin_column = 12, .end_line = 4, .end_column = 20});
        auto fn_span = package.sourceManager().addSpan(
            SourceSpan{.file = file, .begin_line = 3, .begin_column = 17, .end_line = 3, .end_column = 30});

        auto fn = package.createFunction("answer", package.int64Type(), fn_span);
        auto block = package.createBlock(package.function(fn).root_region);
        auto c = package.addConstant(block, 1);
        auto ret = package.addInstForTesting(block, Opcode::Return, {c}, package.voidType(), {}, return_span);

        std::vector<Diagnostic> diags;
        DiagnosticEmitter emitter(package, diags);
        emitter.emit(diag::ReturnTypeMismatch, ret, "int64", "void").note(diag::FunctionDeclaredHere, fn, "void");

        auto out = render(package, diags);
        CHECK(out ==
              "internal compiler error[PIR_RETURN_TYPE_MISMATCH]\n"
              "  at instruction %1 (core.return)\n"
              "  source origin: test.spicy:4:12\n"
              "  detail: returned value has type int64, expected void\n"
              "internal compiler note[PIR_FUNCTION_DECLARED_HERE]\n"
              "  at function %0 \"answer\"\n"
              "  source origin: test.spicy:3:17\n"
              "  detail: function declared with result type void\n");
    }

    TEST_CASE("rendering a malformed entity or span reference does not assert") {
        Package package;

        std::vector<Diagnostic> diags;
        DiagnosticEmitter emitter(package, diags);
        emitter.emit(diag::InvalidOperandId,
                     DiagnosticSite{.source = SourceSpanId{7}, .entity = InstId{42}},
                     size_t{0});
        emitter.emit(diag::OrphanRegions, noSite(), size_t{1});

        auto out = render(package, diags);
        CHECK(out.find("<invalid-span>") != std::string::npos);
        CHECK(out.find("instruction %42") != std::string::npos);
        // The second diagnostic has neither a span nor an entity; it renders with neither line.
        CHECK(out.find("PIR_ORPHAN_REGIONS") != std::string::npos);
        auto orphan_pos = out.find("PIR_ORPHAN_REGIONS");
        CHECK(out.find("  at ", orphan_pos) == std::string::npos);
        CHECK(out.find("  source origin", orphan_pos) == std::string::npos);
    }
}
