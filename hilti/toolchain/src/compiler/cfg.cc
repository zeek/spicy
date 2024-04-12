// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/cfg.h"

#include <algorithm>
#include <iterator>
#include <utility>

#include <hilti/ast/node.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/statements/expression.h>
#include <hilti/ast/statements/if.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/statements/throw.h>
#include <hilti/ast/statements/try.h>
#include <hilti/ast/statements/while.h>
#include <hilti/base/util.h>

namespace hilti {
std::istream& operator>>(std::istream&, Node*) { util::cannotBeReached(); }

std::string node_id(const Node* n) { return util::fmt("%d", n ? n->identity() : 0); }

namespace detail::cfg {

CFG::CFG(const N& root)
    : begin(get_or_add_node(create_meta_node<Start>())), end(get_or_add_node(create_meta_node<End>())) {
    assert(root && root->isA<statement::Block>() && "only building from blocks currently supported");

    auto last = add_block(begin, root->children());
    add_edge(last, end);
}

CFG::NodeP CFG::add_block(NodeP parent, const Nodes& stmts) {
    // If `children` directly has any statements which change control flow like
    // `throw` or `return` any statements after that are unreachable. To model
    // such ASTs we add a flow with all statements up to the "last" semantic
    // statement (either the last child or the control flow statement) to the
    // CFG under `parent`. Statements after that are added as children without
    // parents, and mixed with the previous flow.

    // After this block `last` is the last reachable statement, either end of
    // children or a control flow statement.
    auto last = std::find_if(stmts.begin(), stmts.end(), [](auto&& c) {
        return c && (c->template isA<statement::Return>() || c->template isA<statement::Throw>());
    });
    const bool has_dead_flow = last != stmts.end();
    if ( has_dead_flow )
        last = std::next(last);

    // Add all statements which are part of the normal flow.
    for ( auto&& c : (last != stmts.end() ? Nodes(stmts.begin(), last) : stmts) ) {
        if ( ! c || ! c->isA<Statement>() )
            continue;

        if ( auto&& while_ = c->tryAs<statement::While>() )
            parent = add_while(parent, *while_);

        else if ( auto&& if_ = c->tryAs<statement::If>() )
            parent = add_if(parent, *if_);

        else if ( auto&& try_catch = c->tryAs<statement::Try>() )
            parent = add_try_catch(parent, *try_catch);

        else if ( auto&& return_ = c->tryAs<statement::Return>() )
            parent = add_return(parent, return_->expression());

        else if ( auto&& throw_ = c->tryAs<statement::Throw>() )
            parent = add_return(parent, throw_->expression());

        else {
            auto cc = get_or_add_node(c);

            add_edge(parent, cc);
            add_block(parent, c->children());

            // Update `last` so sibling nodes get chained.
            parent = std::move(cc);
        }
    }

    // Add unreachable flows.
    if ( has_dead_flow && last != stmts.end() ) {
        auto next = add_block(nullptr, Nodes{last, stmts.end()});
        auto mix = get_or_add_node(create_meta_node<Flow>());
        add_edge(parent, mix);
        add_edge(next, mix);
        parent = std::move(mix);
    }

    return parent;
}

CFG::NodeP CFG::add_while(NodeP parent, const statement::While& while_) {
    auto&& condition = get_or_add_node(while_.condition());
    add_edge(std::move(parent), condition);

    auto body_end = add_block(condition, while_.body()->children());
    add_edge(body_end, condition);
    if ( auto&& else_ = while_.else_() ) {
        auto&& else_end = add_block(condition, else_->children());

        auto mix = get_or_add_node(create_meta_node<Flow>());

        add_edge(else_end, mix);
        add_edge(condition, mix);

        return mix;
    }

    return condition;
}

CFG::NodeP CFG::add_if(NodeP parent, const statement::If& if_) {
    auto&& condition = get_or_add_node(if_.condition());
    add_edge(std::move(parent), condition);

    auto true_end = add_block(condition, if_.true_()->children());
    if ( auto false_ = if_.false_() ) {
        auto false_end = add_block(condition, false_->children());
        auto mix = get_or_add_node(create_meta_node<Flow>());

        add_edge(false_end, mix);
        add_edge(true_end, mix);

        return mix;
    }

    return true_end;
}

CFG::NodeP CFG::add_try_catch(const NodeP& parent, const statement::Try& try_catch) {
    auto try_ = add_block(parent, try_catch.body()->children());
    auto mix = get_or_add_node(create_meta_node<Flow>());
    add_edge(try_, mix);

    for ( auto&& catch_ : try_catch.catches() ) {
        auto catch_end = add_block(parent, catch_->body()->children());
        add_edge(catch_end, mix);
    }

    return mix;
}

CFG::NodeP CFG::add_return(const NodeP& parent, const N& expression) {
    if ( expression ) {
        auto r = get_or_add_node(expression);
        add_edge(parent, r);
        return r;
    }

    return parent;
}

std::shared_ptr<const CXXGraph::Node<CFG::N>> CFG::get_or_add_node(const N& n) {
    const auto& id = node_id(n);
    if ( auto x = g.getNode(id) )
        return *x;

    auto y = std::make_shared<CXXGraph::Node<N>>(id, n);
    g.addNode(y);
    return y;
}

void CFG::add_edge(NodeP from, NodeP to) {
    if ( ! from || ! to )
        return;

    if ( const auto& xs = g.outEdges(from);
         xs.end() != std::find_if(xs.begin(), xs.end(), [&](const auto& e) { return e->getNodePair().second == to; }) )
        return;
    else {
        auto e =
            std::make_shared<CXXGraph::DirectedEdge<CFG::N>>(g.getEdgeSet().size(), std::move(from), std::move(to));
        g.addEdge(std::move(e));
        return;
    }
}

std::string CFG::dot() const {
    std::stringstream ss;

    ss << "digraph {\n";

    for ( auto&& n : g.getNodeSet() ) {
        auto&& data = n->getData();
        if ( auto&& meta = data->tryAs<MetaNode>() ) {
            if ( data->isA<Start>() )
                ss << util::fmt("\t%s [label=start shape=Mdiamond];\n", n->getId());

            else if ( data->isA<End>() )
                ss << util::fmt("\t%s [label=end shape=Msquare];\n", n->getId());

            else if ( data->isA<Flow>() )
                ss << util::fmt("\t%s [shape=point];\n", n->getId());

            else
                util::cannotBeReached();
        }

        else
            ss << util::fmt("\t%s [label=\"%s\"];\n", n->getId(), rt::escapeUTF8(data->print(), true));
    }

    for ( auto&& e : g.getEdgeSet() ) {
        auto&& [from, to] = e->getNodePair();
        ss << util::fmt("\t%s -> %s [label=\"%s\"];\n", from->getId(), to->getId(), e->getId());
    }

    ss << "}";

    return ss.str();
}

CXXGraph::T_NodeSet<CFG::N> CFG::unreachable_nodes() const {
    auto xs = nodes();

    // We cannot use `inOutEdges` to get a list of unreachable non-meta nodes
    // since it is completely broken for directed graphs,
    // https://github.com/ZigRazor/CXXGraph/issues/406.

    std::unordered_set<CXXGraph::id_t> has_in_edge;
    for ( auto&& e : g.getEdgeSet() ) {
        auto&& [_, to] = e->getNodePair();
        has_in_edge.insert(to->getId());
    }

    CXXGraph::T_NodeSet<N> result;
    for ( auto&& n : xs ) {
        auto&& data = n->getData();
        if ( data && (! has_in_edge.count(n->getId()) && ! data->isA<MetaNode>()) )
            result.insert(n);
    }

    return result;
}

} // namespace detail::cfg

} // namespace hilti
