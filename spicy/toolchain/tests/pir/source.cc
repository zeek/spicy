// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>

#include <spicy/compiler/detail/pir/ir/package.h>
#include <spicy/compiler/detail/pir/ir/verifier.h>

using namespace spicy::detail::pir::ir;

namespace {

bool hasDiagnostic(const std::vector<Diagnostic>& diags, const DiagnosticDefinition& def) {
    return std::ranges::any_of(diags, [&def](const Diagnostic& d) { return d.definition == def; });
}

} // namespace

TEST_SUITE("pir::ir::SourceManager") {
    TEST_CASE("interns files deterministically") {
        SourceManager sources;

        auto a1 = sources.internFile("a.spicy");
        auto b = sources.internFile("b.spicy");
        auto a2 = sources.internFile("a.spicy");

        CHECK(a1 == a2);
        CHECK(a1 != b);
        CHECK(sources.file(a1).diagnostic_path == "a.spicy");
        CHECK(sources.file(b).diagnostic_path == "b.spicy");
    }

    TEST_CASE("appends spans in order and preserves fields") {
        SourceManager sources;
        auto file = sources.internFile("x.spicy");

        auto s1 = sources.addSpan(
            SourceSpan{.file = file, .begin_line = 3, .begin_column = 5, .end_line = 3, .end_column = 9});
        auto s2 = sources.addSpan(
            SourceSpan{.file = file, .begin_line = 4, .begin_column = 1, .end_line = 4, .end_column = 2});

        CHECK(s1.index == 0);
        CHECK(s2.index == 1);

        const auto& span = sources.span(s1);
        CHECK(span.file == file);
        CHECK(span.begin_line == 3);
        CHECK(span.begin_column == 5);
        CHECK(span.end_line == 3);
        CHECK(span.end_column == 9);
    }

    TEST_CASE("functions and instructions may omit a span") {
        Package package;
        auto fn = package.createFunction("f", package.int64Type());
        auto block = package.createBlock(package.function(fn).root_region);
        auto c = package.addConstant(block, 1);
        package.addReturn(block, c);

        CHECK_FALSE(package.function(fn).span.isSet());
        CHECK_FALSE(package.inst(c).span.isSet());

        auto diags = verify(package);
        CHECK_FALSE(hasDiagnostic(diags, diag::InvalidSourceSpanId));
        CHECK_FALSE(hasDiagnostic(diags, diag::InvalidSourceFileId));
        CHECK_FALSE(hasDiagnostic(diags, diag::MalformedSourceSpanRange));
    }

    TEST_CASE("verification rejects an invalid source span ID without asserting") {
        Package package;
        auto fn = package.createFunction("f", package.int64Type(), SourceSpanId{99});
        auto block = package.createBlock(package.function(fn).root_region);
        auto c = package.addConstant(block, 1);
        package.addReturn(block, c);

        auto diags = verify(package);
        CHECK(hasDiagnostic(diags, diag::InvalidSourceSpanId));
    }

    TEST_CASE("verification rejects an invalid source file ID without asserting") {
        Package package;
        auto span = package.sourceManager().addSpan(SourceSpan{.file = SourceFileId{99}});

        auto fn = package.createFunction("f", package.int64Type(), span);
        auto block = package.createBlock(package.function(fn).root_region);
        auto c = package.addConstant(block, 1);
        package.addReturn(block, c);

        auto diags = verify(package);
        CHECK(hasDiagnostic(diags, diag::InvalidSourceFileId));
    }

    TEST_CASE("verification rejects a reversed known range without asserting") {
        Package package;
        auto file = package.sourceManager().internFile("x.spicy");
        auto span = package.sourceManager().addSpan(
            SourceSpan{.file = file, .begin_line = 5, .begin_column = 1, .end_line = 5, .end_column = 0});

        auto fn = package.createFunction("f", package.int64Type());
        auto block = package.createBlock(package.function(fn).root_region);
        auto c = package.addConstant(block, 1, span);
        package.addReturn(block, c);

        auto diags = verify(package);
        CHECK(hasDiagnostic(diags, diag::MalformedSourceSpanRange));
    }
}
