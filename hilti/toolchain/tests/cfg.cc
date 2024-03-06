// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <algorithm>
#include <fstream>
#include <memory>
#include <vector>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/ctors/bool.h>
#include <hilti/ast/ctors/integer.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/void.h>
#include <hilti/ast/statements/expression.h>
#include <hilti/compiler/detail/cfg.h>

using namespace hilti;
using namespace hilti::detail::cfg;

auto sorted_edges(const CFG& g) {
    auto edges = std::vector(g.edges().begin(), g.edges().end());
    std::sort(edges.begin(), edges.end(), [](auto&& a, auto&& b) { return a->getId() < b->getId(); });
    return edges;
}

/// Helper function to dump a cfg to a file.
// FIXME(bbannier): remove this.
void save_as(const CFG& g, const char* filename) {
    std::fstream f(filename, std::fstream::out);
    f << g.dot();
}

TEST_SUITE_BEGIN("cfg");

TEST_CASE("unreachable statements") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    builder.addReturn();
    builder.addExpression(builder.expression(builder.ctorString("foo1", true)));
    builder.addExpression(builder.expression(builder.ctorString("foo2", true)));

    auto&& ast = builder.block();

    const auto cfg = CFG(ast);

    auto nodes = cfg.nodes();
    auto foo1 =
        std::find_if(nodes.begin(), nodes.end(), [](const auto& n) { return n->getData()->print() == "\"foo1\";"; });
    REQUIRE_NE(foo1, nodes.end());
    auto foo2 =
        std::find_if(nodes.begin(), nodes.end(), [](const auto& n) { return n->getData()->print() == "\"foo2\";"; });
    REQUIRE_NE(foo2, nodes.end());

    auto unreachable = cfg.unreachable_nodes();
    CHECK_EQ(unreachable.size(), 1);
    // Node `foo1` is unreachable since it has no parent.
    CHECK(unreachable.count(*foo1));
    // Node `foo2` is reachable from `foo1`.
    CHECK_FALSE(unreachable.count(*foo2));
}

TEST_CASE("build empty") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    REQUIRE_EQ(cfg.edges().size(), 1);
    auto&& [begin, end] = cfg.edges().begin()->get()->getNodePair();
    CHECK(begin->getData()->isA<Start>());
    CHECK(end->getData()->isA<End>());

    CHECK_EQ(cfg.nodes().size(), 2);
}

TEST_CASE("single statement") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    builder.addExpression(builder.expressionVoid());
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    auto&& edges = sorted_edges(cfg);
    REQUIRE_EQ(edges.size(), 2);
    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "<void expression>;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "<void expression>;");
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());

    auto&& nodes = cfg.nodes();
    CHECK_EQ(nodes.size(), 3);
}

TEST_CASE("two statements") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    builder.addExpression(builder.expressionVoid());
    builder.addExpression(builder.expressionCtor(builder.ctorBool(false)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);

    REQUIRE_EQ(edges.size(), 3);
    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "<void expression>;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "<void expression>;");
        CHECK_EQ(to->getData()->print(), "False;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "False;");
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());

    auto&& nodes = cfg.nodes();
    CHECK_EQ(nodes.size(), 4);
}

TEST_CASE("three statements") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    builder.addExpression(builder.expressionVoid());
    builder.addExpression(builder.expressionCtor(builder.ctorBool(false)));
    builder.addExpression(builder.expressionCtor(builder.ctorSignedInteger(0, 64)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);

    REQUIRE_EQ(edges.size(), 4);
    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "<void expression>;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "<void expression>;");
        CHECK_EQ(to->getData()->print(), "False;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "False;");
        CHECK_EQ(to->getData()->print(), "0;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "0;");
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());

    auto&& nodes = cfg.nodes();
    CHECK_EQ(nodes.size(), 5);
}

struct TestBuilder : public hilti::ExtendedBuilderTemplate<hilti::Builder> {
    using hilti::ExtendedBuilderTemplate<hilti::Builder>::ExtendedBuilderTemplate;
};

// FIXME(bbannier): add test case for `for`.

TEST_CASE("while") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = TestBuilder(ctx.get());
    auto while_ = builder.addWhile(builder.expression(builder.ctorBool(true)));
    while_->addExpression(builder.expression(builder.ctorUnsignedInteger(1, 64)));
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(2, 64)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 5);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "True");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "True");
        CHECK_EQ(to->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "1;");
        CHECK_EQ(to->getData()->print(), "True");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "True");
        CHECK_EQ(to->getData()->print(), "2;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "2;");
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

TEST_CASE("while_else") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = TestBuilder(ctx.get());
    auto [while_, else_] = builder.addWhileElse(builder.expression(builder.ctorBool(true)));
    while_->addExpression(builder.expression(builder.ctorUnsignedInteger(1, 64)));
    else_->addExpression(builder.expression(builder.ctorUnsignedInteger(0, 64)));
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(2, 64)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 8);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "True");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "True");
        CHECK_EQ(to->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "1;");
        CHECK_EQ(to->getData()->print(), "True");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "True");
        CHECK_EQ(to->getData()->print(), "0;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "0;");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "True");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Flow>());
        CHECK_EQ(to->getData()->print(), "2;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "2;");
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

TEST_CASE("if") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = TestBuilder(ctx.get());
    auto if_ = builder.addIf(builder.expression(builder.ctorBool(true)));
    if_->addExpression(builder.expression(builder.ctorUnsignedInteger(1, 64)));
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(2, 64)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 4);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "True");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "True");
        CHECK_EQ(to->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "1;");
        CHECK_EQ(to->getData()->print(), "2;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "2;");
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

TEST_CASE("if_else") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = TestBuilder(ctx.get());
    auto [if_, else_] = builder.addIfElse(builder.expression(builder.ctorBool(true)));
    if_->addExpression(builder.expression(builder.ctorUnsignedInteger(1, 64)));
    else_->addExpression(builder.expression(builder.ctorUnsignedInteger(0, 64)));
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(2, 64)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 7);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "True");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "True");
        CHECK_EQ(to->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "True");
        CHECK_EQ(to->getData()->print(), "0;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(to->getData()->isA<Flow>());
        CHECK_EQ(from->getData()->print(), "0;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(to->getData()->isA<Flow>());
        CHECK_EQ(from->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Flow>());
        CHECK_EQ(to->getData()->print(), "2;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "2;");
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

TEST_CASE("try_catch") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = TestBuilder(ctx.get());
    auto [try_, catch_] = builder.addTry();
    try_->addExpression(builder.expression(builder.ctorString("try", true)));
    catch_.addCatch()->addExpression(builder.expression(builder.ctorString("catch1", true)));
    catch_.addCatch()->addExpression(builder.expression(builder.ctorString("catch2", true)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 7);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "\"try\";");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "\"try\";");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "\"catch1\";");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "\"catch1\";");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "\"catch2\";");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "\"catch2\";");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Flow>());
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

TEST_CASE("return") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(1, 64)));
    builder.addReturn();
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 2);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "1;");
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

TEST_CASE("return nothing") {
    // This is a test for the case for flows with `return` with no expression,
    // i.e., it returns nothing, not even a void.
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(1, 64)));
    builder.addReturn();
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(2, 64)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 4);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "1;");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "2;");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Flow>());
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

TEST_CASE("return multiple") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = TestBuilder(ctx.get());
    builder.addExpression(builder.expression((builder.ctorUnsignedInteger(1, 64))));
    builder.addReturn(builder.ctorString("return1", true));
    builder.addExpression(builder.expression((builder.ctorUnsignedInteger(2, 64))));
    builder.addReturn(builder.ctorString("return2", true));
    builder.addExpression(builder.expression((builder.ctorUnsignedInteger(3, 64))));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 8);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "1;");
        CHECK_EQ(to->getData()->print(), "return \"return1\";");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "2;");
        CHECK_EQ(to->getData()->print(), "return \"return2\";");
    }

    CXXGraph::id_t mix1;
    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "return \"return2\";");
        CHECK(to->getData()->isA<Flow>());
        mix1 = to->getId();
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "3;");
        CHECK(to->getData()->isA<Flow>());
        CHECK_EQ(to->getId(), mix1);
    }

    CXXGraph::id_t mix2;
    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "return \"return1\";");
        CHECK(to->getData()->isA<Flow>());
        mix2 = to->getId();
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getId(), mix1);
        CHECK_EQ(to->getId(), mix2);
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getId(), mix2);
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

TEST_CASE("throw") {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(1, 64)));
    builder.addThrow(builder.expression(builder.ctorString("throw", true)));
    builder.addExpression(builder.expression(builder.ctorUnsignedInteger(2, 64)));
    auto&& ast = builder.block();
    const auto cfg = CFG(ast);

    const auto edges = sorted_edges(cfg);
    CHECK_EQ(edges.size(), 5);

    auto it = edges.begin();

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Start>());
        CHECK_EQ(to->getData()->print(), "1;");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "1;");
        CHECK_EQ(to->getData()->print(), "throw \"throw\";");
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "throw \"throw\";");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK_EQ(from->getData()->print(), "2;");
        CHECK(to->getData()->isA<Flow>());
    }

    {
        auto&& [from, to] = (it++)->get()->getNodePair();
        CHECK(from->getData()->isA<Flow>());
        CHECK(to->getData()->isA<End>());
    }

    CHECK_EQ(it, edges.end());
}

// FIXME(bbannier): implement a test.
TEST_CASE("aliasing" * doctest::skip()) {
    auto ctx = std::make_unique<hilti::ASTContext>(nullptr);
    auto builder = hilti::Builder(ctx.get());

    auto x = builder.declarationGlobalVariable("x", builder.qualifiedType(builder.typeBytes(), Constness::Mutable),
                                               builder.expression(builder.ctorBytes("xyz")));
    builder.call("begin", {builder.id(x->id())});

    CHECK_EQ(builder.block()->children().size(), 0);
}

TEST_SUITE_END();
