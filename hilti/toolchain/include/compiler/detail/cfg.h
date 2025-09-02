// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <hilti/ast/all.h>
#include <hilti/ast/forward.h>
#include <hilti/base/graph.h>

namespace hilti {

namespace node::tag {
constexpr Tag MetaNode = 20000;
constexpr Tag Start = 20001;
constexpr Tag End = 20002;
constexpr Tag Flow = 20003;
} // namespace node::tag

namespace detail::cfg {

/**
 * A "meta" node in a CFG.
 *
 * While a `MetaNode` is a proper `Node` it does not correspond to actual AST
 * information and is intended to hold flow information.
 */
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

/**
 * A meta node for the start of a control flow.
 */
struct Start : MetaNode {
    Start() : MetaNode(NodeTags) {}
    HILTI_NODE_1(Start, MetaNode, final);
};

/**
 * A meta node joining or splitting control flow with no matching source statement.
 */
struct Flow : MetaNode {
    Flow() : MetaNode(NodeTags) {}
    HILTI_NODE_1(Flow, MetaNode, final);
};

/**
 * A meta node to signify end of a scope carrying the source range of that scope.
 */
struct End : MetaNode {
    End(const Node* scope) : MetaNode(NodeTags), scope(scope) {
        assert(scope); // Should always contain a valid scope.
    }

    HILTI_NODE_1(End, MetaNode, final);

    const Node* scope;
};

/**
 * Node in a CFG.
 *
 * This class can deliberately only construct from a fixed set of AST nodes.
 */
class GraphNode {
public:
    GraphNode(operator_::function::Call* x) : _node(x) {}
    GraphNode(Expression* x) : _node(x) {}
    GraphNode(statement::Return* x) : _node(x) {}
    GraphNode(Statement* x) : _node(x) {}
    GraphNode(MetaNode* x) : _node(x) {}
    GraphNode(Declaration* x) : _node(x) {}

    GraphNode() = default;
    GraphNode(const GraphNode&) = default;

    GraphNode& operator=(const GraphNode& x) {
        if ( &x == this )
            return *this;

        _node = x._node;
        return *this;
    }

    Node* operator->() { return _node; }
    const Node* operator->() const { return _node; }

    Node* value() const { return _node; }

    friend bool operator==(const GraphNode& a, const GraphNode& b) { return a._node == b._node; }
    friend bool operator!=(const GraphNode& a, const GraphNode& b) { return ! (a._node == b._node); }

    friend bool operator<(const GraphNode& a, const GraphNode& b) { return a._node < b._node; }

private:
    Node* _node = nullptr;
};

/** Prints out the dot representation of the CFG to a debug stream. */
void dump(logging::DebugStream stream, ASTRoot* root);

} // namespace detail::cfg
} // namespace hilti

namespace std {
template<>
struct hash<hilti::detail::cfg::GraphNode> {
    auto operator()(const hilti::detail::cfg::GraphNode& n) const { return n.value() ? n->identity() : 0; }
};
} // namespace std

namespace hilti::detail::cfg {

/**
 * Dataflow facts about a node.
 */
struct Transfer {
    /** Incoming edges, ordered by declaration they work on. */
    std::unordered_map<Declaration*, std::unordered_set<GraphNode>> in;

    /** Outgoing edges, ordered by declaration they work on. */
    std::unordered_map<Declaration*, std::unordered_set<GraphNode>> out;

    /** The previous nodes killed by this node. */
    std::unordered_map<Declaration*, std::unordered_set<GraphNode>> kill;

    /** Set of declarations this node may alias. */
    std::unordered_set<Declaration*> maybe_alias;

    /**
     * Declarations this graph node generates updates for.
     *
     * For each updated declaration we return the graph node were this value
     * was last updated.
     */
    std::unordered_map<Declaration*, GraphNode> gen;

    /** Set of declaration this node reads. */
    std::unordered_set<Declaration*> read;

    /** Set of declaration this node writes. */
    std::unordered_set<Declaration*> write;

    /**
     * Whether this node has side effects not modelled
     * in the dataflow and should be kept.
     */
    bool keep = false;
};

/**
 * Infrastructure to compute control and dataflow facts about a AST (sub)tree.
 */
class CFG {
public:
    using NodeId = uint64_t;

    /** The underlying graph. */
    using Graph = util::graph::DirectedGraph<GraphNode, NodeId>;

    /**
     * Construct a new CFG.
     *
     * This automatically computes a control flow and data flow facts for the
     * AST under the node.
     *
     * @param root the node pointing to the AST subtree to work on
     */
    CFG(const Node* root);

    /**
     * Remove a node from the graph.
     *
     * This function will connect all upstream neighbors to all downstream neighbors.
     *
     * @param node the node to remove
     */
    void removeNode(Node* node);

    /**
     * Compute a dot representation of the CFG.
     *
     * @return a string with the dot representation
     */
    std::string dot() const;

    /** Get dataflow facts. */
    const auto& dataflow() const { return _dataflow; }

    /** Get control flow. */
    const Graph& graph() const { return _graph; }

    /**
     * Sorts the graph in postorder, from the beginning node. Any nodes that are
     * unreachable downstream from the beginning node are excluded.
     */
    std::deque<GraphNode> postorder() const;

private:
    GraphNode _getOrAddNode(GraphNode n);
    void _addEdge(const GraphNode& from, const GraphNode& to);
    void _populateDataflow();

    GraphNode _addBlock(GraphNode predecessor, const Nodes& stmts, const Node* scope);
    GraphNode _addFor(GraphNode predecessor, const statement::For& for_);
    GraphNode _addWhile(GraphNode predecessor, const statement::While& while_, GraphNode scope_end);
    GraphNode _addIf(GraphNode predecessor, const statement::If& if_);
    GraphNode _addSwitch(GraphNode predecessor, const statement::Switch& switch_);
    GraphNode _addTryCatch(GraphNode predecessor, const statement::Try& try_);
    GraphNode _addReturn(GraphNode predecessor, const statement::Return& return_);
    GraphNode _addThrow(GraphNode predecessor, statement::Throw& throw_, GraphNode scope_end);
    GraphNode _addCall(GraphNode predecessor, operator_::function::Call& call);

    // Add flow for globals if `root` corresponds to a global module block.
    GraphNode _addGlobals(GraphNode predecessor, const Node& root);

    // Add flow for function parameters if `root` corresponds to a function body.
    GraphNode _addParameters(GraphNode predecessor, const Node& root);

    /**
     * Add a new `MetaNode` to the graph.
     *
     * Since meta nodes do not live on the AST they will be stored inside the CFG instance.
     *
     * @tparam T the particular type of `MetaNode` to add
     * @param args constructor arguments for creating the `MetaNode` instance
     * @return a pointer to the added meta node
     */
    template<typename T, typename... Args>
    MetaNode* _createMetaNode(Args... args)
        requires(std::is_base_of_v<MetaNode, T>)
    {
        auto n = std::make_unique<T>(args...);
        auto* r = n.get();
        _meta_nodes.insert(std::move(n));
        return r;
    }

    Graph _graph;

    std::unordered_set<std::unique_ptr<MetaNode>> _meta_nodes;
    std::unordered_map<GraphNode, Transfer> _dataflow;
    GraphNode _begin;
    GraphNode _end;
};

} // namespace hilti::detail::cfg
