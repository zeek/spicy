// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>
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

// A meta node for the end of a control flow.
struct End : MetaNode {
    End() : MetaNode(NodeTags) {}
    HILTI_NODE_1(End, MetaNode, final);
};

// A meta node joining or splitting control flow with no matching source statement.
struct Flow : MetaNode {
    Flow() : MetaNode(NodeTags) {}
    HILTI_NODE_1(Flow, MetaNode, final);
};

// A meta node to signify end of a scope carrying the source range of that scope.
struct ScopeEnd : MetaNode {
    ScopeEnd(const Node* scope) : MetaNode(NodeTags), scope(scope) {
        assert(scope); // Should always contain a valid scope.
    }

    HILTI_NODE_1(ScopeEnd, MetaNode, final);

    const Node* scope;
};

struct Reachability {
    std::unordered_set<Node*> in;
    std::unordered_set<Node*> out;
};

struct Transfer {
    std::unordered_set<Node*> use;
    std::unordered_map<Node*, Node*> gen;
    std::unordered_map<Node*, std::unordered_set<Node*>> kill;
    std::unordered_set<Node*> maybe_alias;

    bool keep = false; // Whether this node should be kept.

    std::optional<Reachability> reachability;
};

class CFG {
public:
    CFG(const Node* root);

    template<typename T, typename... Args, typename = std::enable_if_t<std::is_base_of_v<MetaNode, T>>>
    Node* create_meta_node(Args... args) {
        auto n = std::make_unique<T>(args...);
        auto* r = n.get();
        _meta_nodes.insert(std::move(n));
        return r;
    }

    Node* getOrAddNode(Node* n);
    void addEdge(Node* from, Node* to);

    // Add flow for globals if `root` corresponds to a global module block.
    [[nodiscard]] Node* addGlobals(Node* predecessor, const Node& root);

    std::unordered_set<Node*> unreachableNodes() const;

    std::string dot() const;

    void populateDataflow();
    void populateReachableExpressions();
    std::vector<Node*> unreachableStatements() const;

    util::graph::DirectedGraph<Node*, uintptr_t> g;

private:
    Node* addBlock(Node* predecessor, const Nodes& stmts, const Node* scope);
    Node* addFor(Node* predecessor, const statement::For& for_);
    Node* addWhile(Node* predecessor, const statement::While& while_, Node* scope_end);
    Node* addIf(Node* predecessor, const statement::If& if_);
    Node* addTryCatch(Node* predecessor, const statement::Try& try_);
    Node* addReturn(Node* predecessor, const Node* expression);
    Node* addThrow(Node* predecessor, statement::Throw& throw_, Node* scope_end);
    Node* addCall(Node* predecessor, operator_::function::Call& call);

    std::unordered_set<std::unique_ptr<MetaNode>> _meta_nodes;
    std::unordered_map<Node*, Transfer> _dataflow;
    Node* _begin;
    Node* _end;
};

} // namespace detail::cfg

} // namespace hilti
