// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/ast/all.h>
#include <hilti/base/graph.h>

namespace hilti {

namespace node::tag {
constexpr Tag MetaNode = 20000;
constexpr Tag Start = 20001;
constexpr Tag End = 20002;
constexpr Tag Flow = 20003;
constexpr Tag ScopeEnd = 20004;
} // namespace node::tag

namespace detail::cfg {

struct MetaNode : Node {
    // Some versions of GCC incorrectly diagnose maybe uninitialized members here.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpragmas"
#pragma GCC diagnostic ignored "-Wunknown-warning-option"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    MetaNode(node::Tags node_tags) : Node(nullptr, node_tags, {}, {}) {}
#pragma GCC diagnostic pop

    HILTI_NODE_0(MetaNode, override);
};

// A meta node for the start of a control flow.
struct Start : MetaNode {
    Start() : MetaNode(NodeTags) {}
    HILTI_NODE_1(Start, MetaNode, final);
};

// A meta node joining or splitting control flow with no matching source statement.
struct Flow : MetaNode {
    Flow() : MetaNode(NodeTags) {}
    HILTI_NODE_1(Flow, MetaNode, final);
};

// A meta node to signify end of a scope carrying the source range of that scope.
struct End : MetaNode {
    End(const Node* scope) : MetaNode(NodeTags), scope(scope) {
        assert(scope); // Should always contain a valid scope.
    }

    HILTI_NODE_1(End, MetaNode, final);

    const Node* scope;
};

// The data we hold in the control flow graph.
class GraphNode {
public:
    GraphNode(operator_::function::Call* x) : node(x) {}
    GraphNode(Expression* x) : node(x) {}
    GraphNode(statement::Return* x) : node(x) {}
    GraphNode(Statement* x) : node(x) {}
    GraphNode(MetaNode* x) : node(x) {}
    GraphNode(declaration::LocalVariable* x) : node(x) {}
    GraphNode(declaration::GlobalVariable* x) : node(x) {}

    GraphNode() = default;
    GraphNode(const GraphNode&) = default;

    GraphNode& operator=(const GraphNode& x) {
        if ( &x == this )
            return *this;

        node = x.node;
        return *this;
    }

    Node* operator->() { return node; }
    const Node* operator->() const { return node; }

    Node* value() const { return node; }

    friend bool operator==(const GraphNode& a, const GraphNode& b) { return a.node == b.node; }
    friend bool operator!=(const GraphNode& a, const GraphNode& b) { return ! (a.node == b.node); }

    friend bool operator<(const GraphNode& a, const GraphNode& b) { return a.node < b.node; }

private:
    Node* node = nullptr;
};

} // namespace detail::cfg
} // namespace hilti

namespace std {
template<>
struct hash<hilti::detail::cfg::GraphNode> {
    auto operator()(const hilti::detail::cfg::GraphNode& n) const { return n.value() ? n->identity() : 0; }
};
} // namespace std

namespace hilti::detail::cfg {

struct Reachability {
    std::unordered_set<GraphNode> in;
    std::unordered_set<GraphNode> out;
};

struct Transfer {
    std::unordered_set<Node*> use;
    std::unordered_map<Node*, GraphNode> gen;
    std::unordered_map<Node*, std::unordered_set<GraphNode>> kill;
    std::unordered_set<Node*> maybe_alias;

    bool keep = false; // Whether this node should be kept.

    std::optional<Reachability> reachability;
};

class CFG {
public:
    CFG(const Node* root);

    template<typename T, typename... Args, typename = std::enable_if_t<std::is_base_of_v<MetaNode, T>>>
    MetaNode* create_meta_node(Args... args) {
        auto n = std::make_unique<T>(args...);
        auto* r = n.get();
        _meta_nodes.insert(std::move(n));
        return r;
    }

    GraphNode getOrAddNode(GraphNode n);
    void addEdge(const GraphNode& from, const GraphNode& to);

    std::string dot() const;

    void populateDataflow();
    void populateReachableExpressions();

    const auto& dataflow() const { return _dataflow; }

    util::graph::DirectedGraph<GraphNode, uintptr_t> g;

private:
    GraphNode addBlock(GraphNode predecessor, const Nodes& stmts, const Node* scope);
    GraphNode addFor(GraphNode predecessor, const statement::For& for_);
    GraphNode addWhile(GraphNode predecessor, const statement::While& while_, GraphNode scope_end);
    GraphNode addIf(GraphNode predecessor, const statement::If& if_);
    GraphNode addTryCatch(GraphNode predecessor, const statement::Try& try_);
    GraphNode addReturn(GraphNode predecessor, const statement::Return& return_);
    GraphNode addThrow(GraphNode predecessor, statement::Throw& throw_, GraphNode scope_end);
    GraphNode addCall(GraphNode predecessor, operator_::function::Call& call);

    // Add flow for globals if `root` corresponds to a global module block.
    GraphNode addGlobals(GraphNode predecessor, const Node& root);

    std::unordered_set<std::unique_ptr<MetaNode>> _meta_nodes;
    std::unordered_map<GraphNode, Transfer> _dataflow;
    GraphNode _begin;
    GraphNode _end;
};

} // namespace hilti::detail::cfg
