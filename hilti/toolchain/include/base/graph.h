// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <optional>
#include <set>
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

    const auto& nodes() const { return _nodes; }
    const auto& edges() const { return _edges; }

    /**
     * If the passed value is stored in the graph return its node ID.
     *
     * @param x the value to check
     * @return the node ID of the the value if it is known, or a nullopt
     */
    std::optional<NodeId> getNodeId(const T& x) const {
        if ( auto it = std::find_if(_nodes.begin(), _nodes.end(), [&](auto&& n) { return n.second == x; });
             it != _nodes.end() )
            return it->first;

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

        _nodes.insert({id, std::forward<T>(x)});
        return id;
    }

    /**
     * Remove a node from the graph. This removes all edges to the removed node.
     *
     * @param id the node ID of the node to remove
     */
    void removeNode(NodeId id) {
        _nodes.erase(id);

        std::set<EdgeId> edges_to_remove;
        for ( auto&& [edge_id, nodes] : _edges ) {
            auto&& [from, to] = nodes;

            if ( from == id || to == id )
                edges_to_remove.insert(edge_id);
        }
        for ( auto&& edge_id : edges_to_remove )
            _edges.erase(edge_id);
    }

    /**
     * Get the node for a given node ID.
     *
     * @param id the node ID of the node to get
     * @return a pointer to the node if the node exists, or a nullptr
     */
    const T* getNode(NodeId id) const {
        if ( auto it = _nodes.find(id); it != _nodes.end() )
            return &it->second;

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
    std::vector<NodeId> neighborsDownstream(NodeId id) const { return _neighbors(id, Direction::Out); }

    /**
     * Get upstream neighbors of a node, i.e., nodes connected to the node by
     * an edge where the node is a target.
     *
     * @param id the node ID of the node to query
     * @return a vector of node IDs of upstream neighbor nodes
     */
    std::vector<NodeId> neighborsUpstream(NodeId id) const { return _neighbors(id, Direction::In); }

private:
    std::unordered_map<NodeId, T> _nodes;                         //< nodes in the graph.
    std::unordered_map<EdgeId, std::pair<NodeId, NodeId>> _edges; //< edges in the graph.

    /**
     * Edge direction for edge filtering.
     */
    enum class Direction : char {
        Out, //< edge starts at the node.
        In,  //< edge ends at the node.
    };

    /**
     * Get neighbors of a node.
     *
     * @param id the node ID of the node to query
     * @param dir edge selection
     * @return a vector of node IDs of neighbor nodes
     */
    std::vector<NodeId> _neighbors(NodeId id, Direction dir) const {
        std::vector<NodeId> xs;

        for ( auto&& [edge_id, nodes] : _edges ) {
            auto [from, to] = nodes;

            switch ( dir ) {
                case Direction::Out: {
                    if ( id == from )
                        xs.push_back(to);
                    break;
                }
                case Direction::In: {
                    if ( id == to )
                        xs.push_back(from);
                }
            }
        }

        return xs;
    }
};

} // namespace hilti::util::graph
