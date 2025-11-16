// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <utility>
#include <vector>

namespace hilti::util::graph {

/**
 * A directed graph.
 *
 * @tparam T graph node type
 * @tparam NodeId_ node ID type
 */
template<typename T, typename NodeId_ = std::uint64_t>
    requires std::regular<NodeId_>
class DirectedGraph {
public:
    using NodeId = NodeId_;
    using EdgeId = std::uint64_t;

    /** Information stored for each node, accessible through `nodes()`. */
    struct Node {
        T value;                                  /**< value associated with the node */
        std::vector<EdgeId> edges;                /**< IDs of edges connected to the node */
        std::vector<NodeId> neighbors_upstream;   /**< IDs of upstream (outgoing) neighbor nodes */
        std::vector<NodeId> neighbors_downstream; /**< IDs of downstream (incoming) neighbor nodes */
    };

    const auto& nodes() const { return _nodes; }
    const auto& edges() const { return _edges; }

    /**
     * If the passed value is stored in the graph return its node ID.
     *
     * @param x the value to check
     * @return the node ID of the the value if it is known, or a nullopt
     */
    std::optional<NodeId> getNodeId(const T& x) const {
        if ( auto it = _values.find(x); it != _values.end() )
            return it->second;
        else
            return {};
    }

    /**
     * Add a node to the graph, or return its ID if it already exists.
     *
     * @param x the node to add
     * @param the node ID of the value
     * @return the node ID of the value
     */
    NodeId addNode(T x, NodeId id) {
        if ( auto id = getNodeId(x) )
            return *id;

        _values[x] = id;
        _nodes.insert({id, {std::forward<T>(x), {}, {}}});

        return id;
    }

    /**
     * Remove a node from the graph. This removes all edges to the removed node.
     *
     * @param id the node ID of the node to remove
     */
    void removeNode(NodeId id) {
        auto it = _nodes.find(id);
        if ( it == _nodes.end() )
            return;

        _deleteNodeFromNeighbors(id, it->second.neighbors_upstream, true);
        _deleteNodeFromNeighbors(id, it->second.neighbors_downstream, false);

        for ( auto edge_id : it->second.edges )
            _edges.erase(edge_id);

        _values.erase(it->second.value);
        _nodes.erase(it);
    }

    /**
     * Get the node for a given node ID.
     *
     * @param id the node ID of the node to get
     * @return a pointer to the node if the node exists, or a nullptr
     */
    const T* getNode(NodeId id) const {
        if ( auto it = _nodes.find(id); it != _nodes.end() )
            return &it->second.value;

        return nullptr;
    }

    /**
     * Add an edge to the graph.
     *
     * @param from the node ID of the source node of the edge
     * @param to the node ID of the target node of the edge
     * @return the edge ID of the added edge
     */
    EdgeId addEdge(NodeId from, NodeId to) {
        auto edge_id = _edges.size();
        _edges.insert({edge_id, {from, to}});
        _nodes[from].edges.push_back(edge_id);
        _nodes[from].neighbors_downstream.push_back(to);
        _nodes[to].edges.push_back(edge_id);
        _nodes[to].neighbors_upstream.push_back(from);
        return edge_id;
    }

    /**
     * Get nodes on an edge.
     *
     * @param id the edge ID of the edge to get
     * @return a pair of (source, target) for the edge, or a nullopt
     */
    std::optional<std::pair<NodeId, NodeId>> getEdge(EdgeId id) const {
        if ( auto it = _edges.find(id); it != _edges.end() )
            return it->second;

        return {};
    }

    /**
     * Get downstream neighbors of a node, i.e., nodes connected to the node by
     * an edge where the node is a source.
     *
     * @param id the node ID of the node to query
     * @return a vector of node IDs of downstream neighbor nodes
     */
    const std::vector<NodeId>& neighborsDownstream(NodeId id) const {
        try {
            return _nodes.at(id).neighbors_downstream;
        } catch ( const std::out_of_range& e ) {
            static std::vector<NodeId> empty;
            return empty;
        }
    }

    /**
     * Get upstream neighbors of a node, i.e., nodes connected to the node by
     * an edge where the node is a target.
     *
     * @param id the node ID of the node to query
     * @return a vector of node IDs of upstream neighbor nodes
     */
    const std::vector<NodeId>& neighborsUpstream(NodeId id) const {
        try {
            return _nodes.at(id).neighbors_upstream;
        } catch ( const std::out_of_range& e ) {
            static std::vector<NodeId> empty;
            return empty;
        }
    }

private:
    // Helper to remove references to a node from its neighbors.
    void _deleteNodeFromNeighbors(NodeId id, const std::vector<NodeId>& neighbors, bool upstream) {
        for ( auto nid : neighbors ) {
            auto neighbor = _nodes.find(nid);
            assert(neighbor != _nodes.end());

            if ( upstream )
                neighbor->second.neighbors_downstream.erase(std::remove(neighbor->second.neighbors_downstream.begin(),
                                                                        neighbor->second.neighbors_downstream.end(),
                                                                        id),
                                                            neighbor->second.neighbors_downstream.end());
            else
                neighbor->second.neighbors_upstream.erase(std::remove(neighbor->second.neighbors_upstream.begin(),
                                                                      neighbor->second.neighbors_upstream.end(), id),
                                                          neighbor->second.neighbors_upstream.end());
        }
    }

    std::unordered_map<NodeId, Node> _nodes;                      //< nodes in the graph.
    std::unordered_map<EdgeId, std::pair<NodeId, NodeId>> _edges; //< edges in the graph.
    std::unordered_map<T, NodeId> _values;                        //< mapping from node values to node IDs.
};

} // namespace hilti::util::graph
