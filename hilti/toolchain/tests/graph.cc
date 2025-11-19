// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <doctest/doctest.h>

#include <unordered_map>
#include <vector>

#include <hilti/base/graph.h>

using namespace hilti::util::graph;

TEST_SUITE_BEGIN("graph");

TEST_CASE("DirectedGraph") {
    using G = DirectedGraph<int>;
    G g;

    CHECK(g.nodes().empty());

    auto n1 = g.addNode(11, g.nodes().size() + 1);
    auto n2 = g.addNode(22, g.nodes().size() + 1);

    CHECK_EQ(g.nodes().size(), 2);
    CHECK_EQ(g.nodes().at(n1).value, 11);
    CHECK_EQ(g.nodes().at(n2).value, 22);
    CHECK(g.nodes().at(n1).neighbors_upstream.empty());
    CHECK(g.nodes().at(n1).neighbors_downstream.empty());
    CHECK(g.nodes().at(n2).neighbors_upstream.empty());
    CHECK(g.nodes().at(n2).neighbors_downstream.empty());

    auto e = g.addEdge(n1, n2);

    auto n1_ = g.addNode(11, g.nodes().size() + 1);
    CHECK_EQ(n1, n1_);
    CHECK_EQ(g.nodes().size(), 2);

    const auto* i1 = g.getNode(n1);
    REQUIRE(i1);
    CHECK_EQ(*i1, 11);
    const auto* i2 = g.getNode(n2);
    REQUIRE(i2);
    CHECK_EQ(*i2, 22);

    CHECK_EQ(g.getNodeId(11), n1);
    CHECK_EQ(g.getNodeId(22), n2);

    auto ee = g.getEdge(e);
    REQUIRE(ee);
    CHECK_EQ(*ee, std::pair(n1, n2));

    CHECK_EQ(g.neighborsUpstream(n1), std::vector<G::NodeId>{});
    CHECK_EQ(g.neighborsDownstream(n1), std::vector{n2});
    CHECK_EQ(g.neighborsUpstream(n2), std::vector{n1});
    CHECK_EQ(g.neighborsDownstream(n2), std::vector<G::NodeId>{});

    g.removeNode(n2);
    CHECK_EQ(g.nodes().size(), 1);
    CHECK(g.neighborsDownstream(n1).empty());
}

TEST_SUITE_END();
