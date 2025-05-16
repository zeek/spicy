// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <set>
#include <unordered_map>
#include <utility>
#include <vector>

namespace hilti::util::graph {
enum class Direction : char { Downstream, Upstream };

// FIXME(bbannier): remove customizable NodeId, EdgeId.
template<typename T, typename NodeId_ = std::uint64_t, typename EdgeId_ = std::uint64_t>
struct DirectedGraph {
    using NodeId = NodeId_;
    using EdgeId = EdgeId_;

    std::unordered_map<NodeId, T> _nodes;
    std::unordered_map<EdgeId, std::pair<NodeId, NodeId>> _edges;

    const auto& nodes() const { return _nodes; }
    const auto& edges() const { return _edges; }

    std::optional<NodeId> getNodeId(const T& x) const {
        if ( auto it = std::find_if(_nodes.begin(), _nodes.end(), [&](auto&& n) { return n.second == x; });
             it != _nodes.end() ) {
            return it->first;
        }

        return {};
    }

    // Add a node to the graph, or return its ID if it already exists.
    // FIXME(bbannier): remove id parameter.
    NodeId addNode(T x, NodeId id) {
        if ( auto id = getNodeId(x) )
            return *id;

        // FIXME(bbannier): use this instead of block below.
        // auto node_id = _nodes.size() + 1;
        // _nodes.insert({node_id, std::forward<T>(x)});
        // return node_id;

        _nodes.insert({id, std::forward<T>(x)});
        return id;
    }

    void removeNode(NodeId id) {
        _nodes.erase(id);

        std::set<EdgeId> edges_to_remove;
        for ( auto&& [edgeId, nodes] : _edges ) {
            auto&& [from, to] = nodes;

            if ( from == id || to == id )
                edges_to_remove.insert(edgeId);
        }
        for ( auto&& edgeId : edges_to_remove )
            _edges.erase(edgeId);
    }

    void removeEdge(EdgeId id) { _edges.erase(id); }

    const T* getNode(NodeId id) const {
        if ( auto it = _nodes.find(id); it != _nodes.end() )
            return &it->second;

        return nullptr;
    }

    EdgeId addEdge(NodeId from, NodeId to) {
        auto edge_id = _edges.size();
        _edges.insert({edge_id, {from, to}});
        return edge_id;
    }

    std::optional<std::pair<NodeId, NodeId>> getEdge(EdgeId id) const {
        if ( auto it = _edges.find(id); it != _edges.end() )
            return it->second;

        return {};
    }

    // FIXME(bbannier): this should return a `Vec<(EdgeId, NodeId)`>.
    std::vector<NodeId> neighbors(NodeId id, Direction dir) const {
        std::vector<NodeId> xs;

        for ( auto&& [edge_id, nodes] : _edges ) {
            auto [from, to] = nodes;

            switch ( dir ) {
                case Direction::Downstream: {
                    if ( id == from )
                        xs.push_back(to);
                    break;
                }
                case Direction::Upstream: {
                    if ( id == to )
                        xs.push_back(from);
                }
            }
        }

        return xs;
    }

    std::vector<NodeId> neighborsDownstream(NodeId id) const { return neighbors(id, Direction::Downstream); }
    std::vector<NodeId> neighborsUpstream(NodeId id) const { return neighbors(id, Direction::Upstream); }
};

} // namespace hilti::util::graph
