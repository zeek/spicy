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
    MetaNode(node::Tags node_tags) : Node(nullptr, node_tags, {}, {}) {}
    uint64_t counter = instances++;
    static uint64_t instances;
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
    std::unordered_set<Node*> aliases;

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
        meta_nodes.insert(std::move(n));
        return r;
    }

    Node* get_or_add_node(Node* n);
    void add_edge(Node* from, Node* to);

    // Add flow for globals if `root` corresponds to a global module block.
    [[nodiscard]] Node* add_globals(Node* parent, const Node& root);

    [[nodiscard]]
    Node* add_block(Node* parent, const Nodes& stmts, const Node& scope);
    [[nodiscard]]
    Node* add_for(Node* parent, const statement::For& for_);
    [[nodiscard]]
    Node* add_while(Node* parent, const statement::While& while_);
    [[nodiscard]]
    Node* add_if(Node* parent, const statement::If& if_);
    [[nodiscard]]
    Node* add_try_catch(Node* parent, const statement::Try& try_);
    [[nodiscard]]
    Node* add_return(Node* parent, const Node* expression);
    [[nodiscard]]
    Node* add_throw(Node* parent, statement::Throw& throw_, Node* scope_end);
    [[nodiscard]]
    Node* add_call(Node* parent, operator_::function::Call* call);

    std::unordered_set<Node*> unreachable_nodes() const;

    std::string dot() const;

    void populate_dataflow();
    void populate_reachable_expressions();
    std::vector<Node*> unreachable_statements() const;

    util::graph::DirectedGraph<Node*, uintptr_t> g;

private:
    std::unordered_set<std::unique_ptr<MetaNode>> meta_nodes;
    std::unordered_map<Node*, Transfer> dataflow;
    Node* begin;
    Node* end;
};

} // namespace detail::cfg

} // namespace hilti
