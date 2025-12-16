// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>

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

    GraphNode& operator=(const GraphNode& x) = default;
    GraphNode& operator=(GraphNode&& x) = default;

    Node* operator->() { return _node; }
    const Node* operator->() const { return _node; }

    Node* get() const { return _node; }

    friend bool operator==(const GraphNode& a, const GraphNode& b) { return a._node == b._node; }
    friend bool operator!=(const GraphNode& a, const GraphNode& b) { return ! (a == b); }

    friend bool operator<(const GraphNode& a, const GraphNode& b) { return a._node < b._node; }

private:
    Node* _node = nullptr;
};

} // namespace detail::cfg

} // namespace hilti
namespace std {
template<>
struct hash<hilti::detail::cfg::GraphNode> {
    auto operator()(const hilti::detail::cfg::GraphNode& n) const {
        assert(n.get());
        return reinterpret_cast<std::uintptr_t>(n.get());
    }
};
} // namespace std

namespace hilti::detail {

namespace cfg {
/** Helper function to check whether some `inner` node is a child of an `outer` node. */
bool contains(const Node& outer, const Node& inner);

/** Prints out the dot representation of the CFG to a debug stream. */
void dump(logging::DebugStream stream, ASTRoot* root);

/**
 * Dataflow facts about a node.
 */
struct Transfer {
    /** Incoming edges, ordered by declaration they work on. */
    std::map<Declaration*, std::set<GraphNode>> in;

    /** Outgoing edges, ordered by declaration they work on. */
    std::map<Declaration*, std::set<GraphNode>> out;

    /** The previous nodes killed by this node. */
    std::map<Declaration*, std::set<GraphNode>> kill;

    /** Set of declarations this node may alias. */
    std::set<Declaration*> maybe_alias;

    /**
     * Declarations this graph node generates updates for.
     *
     * For each updated declaration we return the graph node were this value
     * was last updated.
     */
    std::map<Declaration*, GraphNode> gen;

    /** Set of declaration this node reads. */
    std::set<Declaration*> read;

    /** Set of declaration this node writes. */
    std::set<Declaration*> write;

    /**
     * Whether this node has side effects not modelled
     * in the dataflow and should be kept.
     */
    bool keep = false;
};

} // namespace cfg

/**
 * Infrastructure to compute control and dataflow facts about a AST (sub)tree.
 */
class CFG {
public:
    using NodeId = uint64_t;

    /** The underlying graph. */
    using Graph = util::graph::DirectedGraph<cfg::GraphNode, NodeId>;

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
     * @param omit_dataflow if the dot representation should omit dataflow facts
     * @return a string with the dot representation
     */
    std::string dot(bool omit_dataflow) const;

    /** Get dataflow facts. */
    const auto& dataflow() const { return _dataflow; }

    /** Get control flow. */
    const Graph& graph() const { return _graph; }

    /**
     * Sorts the graph in postorder, from the beginning node. Any nodes that are
     * unreachable downstream from the beginning node are excluded.
     */
    std::deque<cfg::GraphNode> postorder() const;

    /** Get the starting node. */
    cfg::GraphNode begin() const { return _begin; }

    /** Get the end node. */
    cfg::GraphNode end() const { return _end; }

private:
    cfg::GraphNode _getOrAddNode(cfg::GraphNode n);
    void _addEdge(const cfg::GraphNode& from, const cfg::GraphNode& to);
    void _populateDataflow();

    cfg::GraphNode _addBlock(cfg::GraphNode predecessor, const Nodes& stmts, const Node* scope);
    cfg::GraphNode _addFor(cfg::GraphNode predecessor, const statement::For& for_);
    cfg::GraphNode _addWhile(cfg::GraphNode predecessor, const statement::While& while_, cfg::GraphNode scope_end);
    cfg::GraphNode _addIf(cfg::GraphNode predecessor, const statement::If& if_);
    cfg::GraphNode _addSwitch(cfg::GraphNode predecessor, const statement::Switch& switch_);
    cfg::GraphNode _addTryCatch(cfg::GraphNode predecessor, const statement::Try& try_);
    cfg::GraphNode _addReturn(cfg::GraphNode predecessor, const statement::Return& return_);
    cfg::GraphNode _addThrow(cfg::GraphNode predecessor, statement::Throw& throw_, cfg::GraphNode scope_end);
    cfg::GraphNode _addCall(cfg::GraphNode predecessor, operator_::function::Call& call);

    // Add flow for globals if `root` corresponds to a global module block.
    cfg::GraphNode _addGlobals(cfg::GraphNode predecessor, const Node& root);

    // Add flow for function parameters if `root` corresponds to a function body.
    cfg::GraphNode _addParameters(cfg::GraphNode predecessor, const Node& root);

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
    cfg::MetaNode* _createMetaNode(Args... args)
        requires(std::is_base_of_v<cfg::MetaNode, T>)
    {
        auto n = std::make_unique<T>(args...);
        auto* r = n.get();
        _meta_nodes.insert(std::move(n));
        return r;
    }

    Graph _graph;

    std::set<std::unique_ptr<cfg::MetaNode>> _meta_nodes;
    std::map<cfg::GraphNode, cfg::Transfer> _dataflow;
    cfg::GraphNode _begin;
    cfg::GraphNode _end;
};

namespace cfg {

/**
 * A cache storing CFGs already computed for blocks of an AST. This computes
 * CFGs on first access and then stores them for subsequent requests. The cache
 * assumes that CFGs remain valid until explicit invalidated through one of the
 * provided invalidation methods.
 */
class Cache {
public:
    /**
     * Returns the control flow graph for a given block.
     *
     * The CFG is created on first request and cached for subsequent calls,
     * until either explicitly invalidated or until the cache is cleared.
     *
     * @param block the block to get the CFG for, which must be part of a
     * function or module
     * @return the CFG (which will actually be the CFG for the outermost block
     * containing the given block, i.e., for the function or module body
     * containing it)
     */
    CFG* get(statement::Block* block);

    /**
     * Removes any cached CFG for the function or module containing a given
     * block. The CFG will then be re-computed next time it's requested.
     *
     * @param block block whose containing function/module's CFG will be
     * invalidated; the block must indeed be part of a function or module
     * @return true if a cached CFG was found and invalidated, false otherwise
     */
    bool invalidate(statement::Block* block);

    /**
     * Removes all CFGs cached for a module. This includes the module's global
     * stsatement block as well as all functions defined in the module. Each of
     * these CFGs will then be re-computed next time they're requested.
     *
     * @param module the module whose cached CFGs to invalidate
     * @return true if any cached CFGs were found and invalidated, false otherwise
     */
    bool invalidate(declaration::Module* module);

    /**
     * Invalidates any cached CFGs that correspond to blocks no longer part of
     * the AST. This should be called after AST mutations that may have removed
     * any blocks from the AST.
     */
    void prune();

    /** Clears the entire cache. */
    void clear() {
        _blocks.clear();
        _modules.clear();
    }

    /**
     * Confirms that the cached CFGs are all still valid. To do so, it
     * recomputes the CFGs for all cached blocks and compares them to the
     * cached ones. Aborts with an internal error if differences are found.
     * This is intended for debugging purposes only and can be expensive to
     * perform.
     */
    void checkValidity() const;

private:
    // Maps from blocks to pairs of the blocks containing modules and their
    // computed & cached CFGs. Using retained pointers to ensure the blocks
    // stay valid as long as they're in the cache. The module pointers will
    // remain valid as long as the blocks do because they are kept alive by
    // _modules.
    std::unordered_map<node::RetainedPtr<statement::Block>, std::pair<declaration::Module*, std::unique_ptr<CFG>>>
        _blocks;

    // Maps from module to all blocks part of that module that have cached CFGs
    // stored in _blocks.
    std::unordered_map<node::RetainedPtr<declaration::Module>, std::unordered_set<statement::Block*>> _modules;
};

} // namespace cfg
} // namespace hilti::detail
