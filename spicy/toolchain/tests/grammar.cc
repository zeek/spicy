// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bytes.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/compiler/init.h>

#include <spicy/compiler/detail/codegen/grammar.h>
#include <spicy/compiler/detail/codegen/productions/all.h>
#include <spicy/spicy.h>

using Ps = std::vector<std::unique_ptr<spicy::detail::codegen::Production>>;

template<class... Args>
static auto makeProds(Args... args) {
    std::vector<std::unique_ptr<spicy::detail::codegen::Production>> rv;
    (rv.emplace_back(std::move(args)), ...);
    return rv;
}

static auto literal(hilti::ASTContext* ctx, const std::string& symbol, std::string value) {
    auto* c = hilti::ctor::Bytes::create(ctx, std::move(value));
    return std::make_unique<spicy::detail::codegen::production::Ctor>(ctx, symbol, c);
}

static auto sequence(hilti::ASTContext* ctx, const std::string& symbol, Ps l) {
    return std::make_unique<spicy::detail::codegen::production::Sequence>(ctx, symbol, std::move(l));
}

static auto variable(hilti::ASTContext* ctx, const std::string& symbol, hilti::UnqualifiedType* t) {
    return std::make_unique<
        spicy::detail::codegen::production::Variable>(ctx, symbol,
                                                      hilti::QualifiedType::create(ctx, t, hilti::Constness::Mutable));
}

static auto typeLiteral(hilti::ASTContext* ctx, const std::string& symbol, spicy::UnqualifiedType* t) {
    return std::make_unique<
        spicy::detail::codegen::production::TypeLiteral>(ctx, symbol,
                                                         hilti::QualifiedType::create(ctx, t, hilti::Constness::Const));
}

static auto resolved(hilti::ASTContext* ctx) {
    auto x = std::make_unique<spicy::detail::codegen::production::Deferred>(ctx);
    return std::make_pair(x.get(), std::move(x));
}

template<typename T>
static auto reference(hilti::ASTContext* ctx, const std::unique_ptr<T>& p) {
    return std::make_unique<spicy::detail::codegen::production::Reference>(ctx, p.get());
}

static auto lookAhead(hilti::ASTContext* ctx, const std::string& symbol,
                      std::unique_ptr<spicy::detail::codegen::Production> a1,
                      std::unique_ptr<spicy::detail::codegen::Production> a2, hilti::Expression* condition = nullptr) {
    return std::make_unique<
        spicy::detail::codegen::production::LookAhead>(ctx, symbol, std::move(a1), std::move(a2),
                                                       spicy::detail::codegen::production::look_ahead::Default::None,
                                                       condition);
}

static auto epsilon(hilti::ASTContext* ctx) {
    return std::make_unique<spicy::detail::codegen::production::Epsilon>(ctx);
}

static hilti::Result<hilti::Nothing> finalize(spicy::detail::codegen::Grammar* g,
                                              std::unique_ptr<spicy::detail::codegen::Production> root) {
    if ( auto result = g->setRoot(std::move(root)); ! result )
        return result;

    if ( auto result = g->finalize(); ! result )
        return result;

    return hilti::Nothing();
}

TEST_SUITE_BEGIN("Grammar");

TEST_CASE("basic") {
    hilti::ASTContext ctx(nullptr);

    auto g = spicy::detail::codegen::Grammar("basic");
    auto prods = makeProds(literal(&ctx, "l1", "l1-val"), literal(&ctx, "l2", "l2-val"), literal(&ctx, "l3", "l3-val"));
    auto r = sequence(&ctx, "S", std::move(prods));
    CHECK(finalize(&g, std::move(r)));
}

TEST_CASE("example1") {
    // NOLINTBEGIN(readability-identifier-naming)

    // Simple example grammar from
    //
    // http://www.cs.uky.edu/~lewis/essays/compilers/td-parse.html
    //
    // Ambiguity expected.

    hilti::init();
    hilti::ASTContext ctx(nullptr);

    auto g = spicy::detail::codegen::Grammar("example1");

    auto a = literal(&ctx, "a1", "a");
    auto a_r1 = reference(&ctx, a);
    auto b = literal(&ctx, "b1", "b");
    auto b_r1 = reference(&ctx, b);
    auto c = literal(&ctx, "c1", "c");
    auto c_r1 = reference(&ctx, c);

    auto [A_, A] = resolved(&ctx);
    auto A_r1 = reference(&ctx, A);
    auto A_r2 = reference(&ctx, A);
    auto A_r3 = reference(&ctx, A);

    auto [C_, C] = resolved(&ctx);

    auto [D_, D] = resolved(&ctx);
    auto D_r1 = reference(&ctx, D);

    auto cC = sequence(&ctx, "cC", makeProds(std::move(c), std::move(C)));
    auto bD = sequence(&ctx, "bD", makeProds(std::move(b), std::move(D)));
    auto AD = sequence(&ctx, "AD", makeProds(std::move(A), std::move(D_r1)));
    auto aA = sequence(&ctx, "aA", makeProds(std::move(a), std::move(A_r1)));

    g.resolve(A_, lookAhead(&ctx, "A", epsilon(&ctx), std::move(a_r1)));
    auto B = lookAhead(&ctx, "B", epsilon(&ctx), std::move(bD));
    g.resolve(C_, lookAhead(&ctx, "C", std::move(AD), std::move(b_r1)));
    g.resolve(D_, lookAhead(&ctx, "D", std::move(aA), std::move(c_r1)));

    auto ABA = sequence(&ctx, "ABA", makeProds(std::move(A_r2), std::move(B), std::move(A_r3)));
    auto S = lookAhead(&ctx, "S", std::move(ABA), std::move(cC));

    auto rc = finalize(&g, std::move(S));
    CHECK_EQ(rc,
             hilti::Result<hilti::Nothing>(hilti::result::Error(
                 "grammar example1, production A is ambiguous for look-ahead symbol(s) { b\"a\" (const bytes) }\n")));
    // NOLINTEND(readability-identifier-naming)
}

TEST_CASE("example2") {
    //  Simple example grammar from "Parsing Techniques", Fig. 8.9
    // NOLINTBEGIN(readability-identifier-naming)
    hilti::init();
    hilti::ASTContext ctx(nullptr);
    auto g = spicy::detail::codegen::Grammar("example2");

    auto hs = literal(&ctx, "hs", "#");
    auto pl = literal(&ctx, "pl", "(");
    auto pr = literal(&ctx, "pr", ")");
    auto no = literal(&ctx, "no", "!");
    auto qu = literal(&ctx, "qu", "?");
    auto st = variable(&ctx, "st", hilti::type::Bytes::create(&ctx));
    auto st_r1 = reference(&ctx, st);

    auto [FsQ_, FsQ] = resolved(&ctx);
    auto [SS_, SS] = resolved(&ctx);
    auto [FFs_, FFs] = resolved(&ctx);

    auto F = sequence(&ctx, "Fact", makeProds(std::move(no), std::move(st)));
    auto Q = sequence(&ctx, "Question", makeProds(std::move(qu), std::move(st_r1)));
    auto S = lookAhead(&ctx, "Session", std::move(FsQ), std::move(SS));
    auto S_r1 = reference(&ctx, S);
    auto S_r2 = reference(&ctx, S);

    g.resolve(SS_, sequence(&ctx, "SS", makeProds(std::move(pl), std::move(S), std::move(pr), std::move(S_r1))));
    auto Fs = lookAhead(&ctx, "Facts", std::move(FFs), epsilon(&ctx));
    auto Fs_r1 = reference(&ctx, Fs);
    g.resolve(FsQ_, sequence(&ctx, "FsQ", makeProds(std::move(Fs), std::move(Q))));
    g.resolve(FFs_, sequence(&ctx, "FFs", makeProds(std::move(F), std::move(Fs_r1))));
    auto root = sequence(&ctx, "Start", makeProds(std::move(S_r2), std::move(hs)));
    CHECK(finalize(&g, std::move(root)));
    // NOLINTEND(readability-identifier-naming)
}

TEST_CASE("example3") {
    hilti::init();
    hilti::ASTContext ctx(nullptr);
    auto g = spicy::detail::codegen::Grammar("example3");

    auto hdrkey = ::typeLiteral(&ctx, "HdrKey", hilti::type::Bytes::create(&ctx));
    auto hdrval = ::typeLiteral(&ctx, "HdrVal", hilti::type::Bytes::create(&ctx));
    auto colon = literal(&ctx, "colon", ":");
    auto ws = literal(&ctx, "ws", "[ \t]*");
    auto ws_r1 = reference(&ctx, ws);
    auto nl = literal(&ctx, "nl", "[\r\n]");
    auto nl_r1 = reference(&ctx, nl);
    auto header = sequence(&ctx, "Header",
                           makeProds(std::move(hdrkey), std::move(ws), std::move(colon), std::move(ws_r1),
                                     std::move(hdrval), std::move(nl)));
    auto [list1_, list1] = resolved(&ctx);
    auto list2 = lookAhead(&ctx, "List2", std::move(list1), epsilon(&ctx));
    auto list2_r1 = reference(&ctx, list2);
    g.resolve(list1_, sequence(&ctx, "List1", makeProds(std::move(header), std::move(list2))));
    auto all = lookAhead(&ctx, "All", std::move(list2_r1), std::move(nl_r1));
    CHECK(finalize(&g, std::move(all)));
}

TEST_CASE("example4") {
    hilti::init();
    hilti::ASTContext ctx(nullptr);
    auto g = spicy::detail::codegen::Grammar("example4");

    auto hdrkey = literal(&ctx, "hk", "hv");
    auto hdrval = literal(&ctx, "hv", "hk");
    auto colon = literal(&ctx, "colon", ":");
    auto ws = literal(&ctx, "ws", "[ \t]*");
    auto nl = literal(&ctx, "nl", "[\r\n]");
    // auto header = sequence(&ctx, "Header", {hdrkey, ws, colon, ws, hdrval, nl});
    auto [all_, all] = resolved(&ctx);
    auto [list1_, list1] = resolved(&ctx);
    auto list2 = lookAhead(&ctx, "List2", std::move(ws), epsilon(&ctx));
    auto list2_r1 = reference(&ctx, list2);
    g.resolve(list1_, sequence(&ctx, "List1", makeProds(std::move(list2))));
    g.resolve(all_, sequence(&ctx, "All", makeProds(std::move(list2_r1), std::move(colon))));
    CHECK(finalize(&g, std::move(all)));
}

TEST_SUITE_END();
