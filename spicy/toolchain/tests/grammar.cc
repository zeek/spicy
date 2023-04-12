// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <utility>

#include <hilti/ast/ctors/bytes.h>
#include <hilti/ast/expressions/ctor.h>

#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/productions/all.h>
#include <spicy/spicy.h>

static auto literal(const std::string& symbol, std::string value) {
    auto c = hilti::ctor::Bytes(std::move(value));
    return spicy::detail::codegen::production::Ctor(symbol, std::move(c));
}

static auto sequence(const std::string& symbol, std::vector<spicy::detail::codegen::Production> l) {
    return spicy::detail::codegen::production::Sequence(symbol, std::move(l));
}

static auto variable(const std::string& symbol, spicy::Type t) {
    return spicy::detail::codegen::production::Variable(symbol, std::move(t));
}

static auto type_literal(const std::string& symbol, spicy::Type t) {
    return spicy::detail::codegen::production::TypeLiteral(symbol, std::move(t));
}

static auto unresolved() { return spicy::detail::codegen::production::Unresolved(); }

static auto lookAhead(const std::string& symbol, spicy::detail::codegen::Production a1,
                      spicy::detail::codegen::Production a2) {
    return spicy::detail::codegen::production::LookAhead(symbol, std::move(a1), std::move(a2),
                                                         spicy::detail::codegen::production::look_ahead::Default::None);
}

static auto epsilon() { return spicy::detail::codegen::production::Epsilon(); }

static hilti::Result<hilti::Nothing> finalize(spicy::detail::codegen::Grammar* g,
                                              const spicy::detail::codegen::Production& root) {
    if ( auto result = g->setRoot(root); ! result )
        return result;

    if ( auto result = g->finalize(); ! result )
        return result;

    return hilti::Nothing();
}

TEST_SUITE_BEGIN("Grammar");

TEST_CASE("basic") {
    auto g = spicy::detail::codegen::Grammar("basic");
    auto l1 = literal("l1", "l1-val");
    auto l2 = literal("l2", "l2-val");
    auto l3 = literal("l3", "l3-val");
    auto r = sequence("S", {l1, l2, l3});
    CHECK(finalize(&g, r));
}

TEST_CASE("example1") {
    // Simple example grammar from
    //
    // http://www.cs.uky.edu/~lewis/essays/compilers/td-parse.html
    //
    // Ambiguity expected.

    auto g = spicy::detail::codegen::Grammar("example1");

    auto a = literal("a", "a");
    auto b = literal("b", "b");
    auto c = literal("c", "c");
    auto d = literal("d", "d");

    auto A = unresolved();
    auto C = unresolved();
    auto D = unresolved();

    auto cC = sequence("cC", {c, C});
    auto bD = sequence("bD", {b, D});
    auto AD = sequence("AD", {A, D});
    auto aA = sequence("aA", {a, A});

    g.resolve(&A, lookAhead("A", epsilon(), a));
    auto B = lookAhead("B", epsilon(), bD);
    g.resolve(&C, lookAhead("C", AD, b));
    g.resolve(&D, lookAhead("D", aA, c));

    auto ABA = sequence("ABA", {A, B, A});
    auto S = lookAhead("S", ABA, cC);

    CHECK_EQ(finalize(&g, S),
             hilti::Result<hilti::Nothing>(hilti::result::Error(
                 "grammar example1, production A is ambiguous for look-ahead symbol(s) { b\"a\" (bytes) }\n")));
}

TEST_CASE("example2") {
    //  Simple example grammar from "Parsing Techniques", Fig. 8.9

    auto g = spicy::detail::codegen::Grammar("example2");

    auto hs = literal("hs", "#");
    auto pl = literal("pl", "(");
    auto pr = literal("pr", ")");
    auto no = literal("no", "!");
    auto qu = literal("qu", "?");
    auto st = variable("st", spicy::type::Bytes());

    auto FsQ = unresolved();
    auto SS = unresolved();
    auto FFs = unresolved();

    auto F = sequence("Fact", {no, st});
    auto Q = sequence("Question", {qu, st});
    auto S = lookAhead("Session", FsQ, SS);
    g.resolve(&SS, sequence("SS", {pl, S, pr, S}));
    auto Fs = lookAhead("Facts", FFs, epsilon());
    g.resolve(&FsQ, sequence("FsQ", {Fs, Q}));
    g.resolve(&FFs, sequence("FFs", {F, Fs}));
    auto root = sequence("Start", {S, hs});
    CHECK(finalize(&g, root));
}

TEST_CASE("example3") {
    auto g = spicy::detail::codegen::Grammar("example3");

    auto hdrkey = ::type_literal("HdrKey", spicy::type::Bytes());
    auto hdrval = ::type_literal("HdrVal", spicy::type::Bytes());
    auto colon = literal("colon", ":");
    auto ws = literal("ws", "[ \t]*");
    auto nl = literal("nl", "[\r\n]");
    auto header = sequence("Header", {hdrkey, ws, colon, ws, hdrval, nl});
    auto list1 = unresolved();
    auto list2 = lookAhead("List2", list1, epsilon());
    g.resolve(&list1, sequence("List1", {header, list2}));
    auto all = lookAhead("All", list2, nl);
    CHECK(finalize(&g, all));
}

TEST_CASE("example4") {
    auto g = spicy::detail::codegen::Grammar("example4");

    auto hdrkey = literal("hk", "hv");
    auto hdrval = literal("hv", "hk");
    auto colon = literal("colon", ":");
    auto ws = literal("ws", "[ \t]*");
    auto nl = literal("nl", "[\r\n]");
    // auto header = sequence("Header", {hdrkey, ws, colon, ws, hdrval, nl});
    auto all = unresolved();
    auto list1 = unresolved();
    auto list2 = lookAhead("List2", ws, epsilon());
    g.resolve(&list1, sequence("List1", {list2}));
    g.resolve(&all, sequence("All", {list2, colon}));
    CHECK(finalize(&g, all));
}

TEST_SUITE_END();
