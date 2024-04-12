// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/node.h>

#include <CXXGraph/CXXGraph.hpp>

namespace hilti {

// Needed for CXXGraph, but left unimplemented.
std::istream& operator>>(std::istream&, Node*);

namespace node::tag {
enum : uint16_t {
    MetaNode = 10000,
    Start,
    End,
    Flow,
};
}

namespace detail::cfg {
struct MetaNode : Node {
    MetaNode(node::Tags node_tags) : Node(nullptr, node_tags, {}, {}) {}
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

class CFG {
public:
    using N = Node*;
    using NodeP = std::shared_ptr<const CXXGraph::Node<N>>;

    CFG(const N& root);


    template<typename T, typename = std::enable_if_t<std::is_base_of_v<MetaNode, T>>>
    N create_meta_node() {
        auto n = std::make_unique<T>();
        auto* r = n.get();
        meta_nodes.insert(std::move(n));
        return r;
    }

    NodeP get_or_add_node(const N& n);
    void add_edge(NodeP from, NodeP to);

    NodeP add_block(NodeP parent, const Nodes& stmts);
    NodeP add_while(NodeP parent, const statement::While& while_);
    NodeP add_if(NodeP parent, const statement::If& if_);
    NodeP add_try_catch(const NodeP& parent, const statement::Try& try_);
    NodeP add_return(const NodeP& parent, const N& expression);

    const auto& edges() const { return g.getEdgeSet(); }
    auto nodes() const { return g.getNodeSet(); }

    CXXGraph::T_NodeSet<N> unreachable_nodes() const;

    std::string dot() const;

private:
    CXXGraph::Graph<N> g;

    std::unordered_set<std::unique_ptr<MetaNode>> meta_nodes;
    NodeP begin;
    NodeP end;
};
} // namespace detail::cfg

} // namespace hilti
