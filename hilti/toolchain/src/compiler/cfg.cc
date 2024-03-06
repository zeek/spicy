// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/cfg.h"

#include <CXXGraph/Node/Node_decl.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/rt/util.h>

#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/assign.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/location.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operators/function.h>
#include <hilti/ast/statement.h>
#include <hilti/ast/statements/assert.h>
#include <hilti/ast/statements/block.h>
#include <hilti/ast/statements/break.h>
#include <hilti/ast/statements/comment.h>
#include <hilti/ast/statements/continue.h>
#include <hilti/ast/statements/declaration.h>
#include <hilti/ast/statements/expression.h>
#include <hilti/ast/statements/for.h>
#include <hilti/ast/statements/if.h>
#include <hilti/ast/statements/return.h>
#include <hilti/ast/statements/set_location.h>
#include <hilti/ast/statements/throw.h>
#include <hilti/ast/statements/try.h>
#include <hilti/ast/statements/while.h>
#include <hilti/ast/statements/yield.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/util.h>
#include <hilti/hilti/ast/types/bytes.h>
#include <hilti/hilti/ast/types/list.h>
#include <hilti/hilti/ast/types/map.h>
#include <hilti/hilti/ast/types/set.h>
#include <hilti/hilti/ast/types/stream.h>
#include <hilti/hilti/ast/types/vector.h>

namespace hilti {
std::istream& operator>>(std::istream&, Node*) { util::cannotBeReached(); }

static std::string node_id(const Node* n) { return util::fmt("%d", n ? n->identity() : 0); }

namespace detail::cfg {

uint64_t MetaNode::instances = 0;

// Ad-hoc sorting for nodes.
//
// FIXME(bbannier): We only need this as we have no way to access graph nodes
// in a deterministic order below. Drop this should we switch to a graph
// library which provides that.
static bool operator<(const Node& a, const Node& b) {
    const auto* metaA = a.tryAs<MetaNode>();
    const auto* metaB = b.tryAs<MetaNode>();

    // Distinguish MetaNodes by counter.
    if ( metaA && metaB ) {
        if ( metaA != metaB )
            assert(metaA->counter != metaB->counter);
        return metaA->counter < metaB->counter;
    }

    // MetaNodes sort before other Nodes.
    else if ( metaA && ! metaB ) {
        return true;
    }
    else if ( ! metaA && metaB ) {
        return false;
    }

    // Other nodes are distinguished by content hash.
    else {
        auto hasher = std::hash<std::string>();
        return hasher(a.print()) < hasher(b.print());
    }
}

// Helper function to detect whether values of a type can alias their inputs.
static bool is_aliasing_type(const UnqualifiedType& type) {
    // TODO(bbannier): Make this part of e.g., `UnqualifiedType` instead of a hardcoded list of types here?
    return type.isA<type::stream::View>() ||     //
           type.isA<type::bytes::Iterator>() ||  //
           type.isA<type::list::Iterator>() ||   //
           type.isA<type::map::Iterator>() ||    //
           type.isA<type::set::Iterator>() ||    //
           type.isA<type::stream::Iterator>() || //
           type.isA<type::vector::Iterator>();
}

static bool contains(const Node& outer, const Node& inner) {
    const auto* n = &inner;

    do {
        if ( n == &outer )
            return true;
        n = n->parent();
    } while ( n );

    return false;
}

// We cannot use `inEdges` since it is completely broken for directed graphs,
// https://github.com/ZigRazor/CXXGraph/issues/406.
CXXGraph::T_EdgeSet<CFG::N> inEdges(const CXXGraph::Graph<CFG::N>& g, const CXXGraph::Node<CFG::N>* n) {
    CXXGraph::T_EdgeSet<CFG::N> in;

    for ( auto&& e : g.getEdgeSet() ) {
        auto&& [_, to] = e->getNodePair();

        if ( to.get() == n )
            in.insert(e);
    }

    return in;
}

// We cannot use `outEdges` since it is completely broken for directed graphs,
// https://github.com/ZigRazor/CXXGraph/issues/406.
CXXGraph::T_EdgeSet<CFG::N> outEdges(const CXXGraph::Graph<CFG::N>& g, const CXXGraph::Node<CFG::N>* n) {
    CXXGraph::T_EdgeSet<CFG::N> out;

    for ( auto&& e : g.getEdgeSet() ) {
        auto&& [from, _] = e->getNodePair();

        if ( from.get() == n )
            out.insert(e);
    }

    return out;
}


CFG::CFG(const Node* root)
    : begin(get_or_add_node(create_meta_node<Start>())), end(get_or_add_node(create_meta_node<End>())) {
    assert(root && root->isA<statement::Block>() && "only building from blocks currently supported");

    begin = add_globals(begin, *root);
    auto last = add_block(begin, root->children(), *root);
    if ( last != end )
        add_edge(last, end);
}

CFG::NodeP CFG::add_globals(NodeP parent, const Node& root) {
    auto* p = root.parent();
    if ( ! p )
        return parent;

    auto* mod = p->tryAs<declaration::Module>();
    if ( ! mod )
        return parent;

    // A global variables with an init statement since they are effectively statements.
    for ( auto* decl : mod->declarations() ) {
        auto* global = decl->tryAs<declaration::GlobalVariable>();
        if ( ! global )
            continue;

        if ( ! global->init() )
            continue;

        auto stmt = get_or_add_node(global);
        add_edge(parent, stmt);
        parent = std::move(stmt);
    }

    return parent;
}

CFG::NodeP CFG::add_block(NodeP parent, const Nodes& stmts, const Node& scope) {
    // If `children` directly has any statements which change control flow like
    // `throw` or `return` any statements after that are unreachable. To model
    // such ASTs we add a flow with all statements up to the "last" semantic
    // statement (either the last child or the control flow statement) to the
    // CFG under `parent`. Statements after that are added as children without
    // parents, and mixed with the previous flow.

    // After this block `last` is the last reachable statement, either end of
    // children or a control flow statement.
    auto last = std::find_if(stmts.begin(), stmts.end(), [](auto&& c) {
        return c && (c->template isA<statement::Return>() || c->template isA<statement::Throw>() ||
                     c->template isA<statement::Continue>() || c->template isA<statement::Break>());
    });
    const bool has_dead_flow = last != stmts.end();
    if ( has_dead_flow )
        last = std::next(last);

    // Node this block will eventually flow into.
    auto scope_end = get_or_add_node(create_meta_node<ScopeEnd>(&scope));

    // Add all statements which are part of the normal flow.
    for ( auto&& c : (last != stmts.end() ? Nodes(stmts.begin(), last) : stmts) ) {
        if ( ! c )
            continue;

        if ( auto&& while_ = c->tryAs<statement::While>() )
            parent = add_while(parent, *while_);

        else if ( auto&& for_ = c->tryAs<statement::For>() )
            parent = add_for(parent, *for_);

        else if ( auto&& if_ = c->tryAs<statement::If>() )
            parent = add_if(parent, *if_);

        else if ( auto&& try_catch = c->tryAs<statement::Try>() )
            parent = add_try_catch(parent, *try_catch);

        else if ( auto&& throw_ = c->tryAs<statement::Throw>() )
            parent = add_throw(parent, throw_->expression(), scope_end);

        else if ( auto&& return_ = c->tryAs<statement::Return>() )
            parent = add_return(parent, return_->expression());

        else if ( c->isA<statement::Continue>() || c->isA<statement::Break>() )
            // `continue`/`break` statements only add flow, but no data.
            parent = add_return(parent, nullptr);

        else if ( auto&& call = c->tryAs<operator_::function::Call>() )
            parent = add_call(parent, call);

        else if ( auto&& block = c->tryAs<statement::Block>() )
            parent = add_block(parent, block->statements(), *block);

        else {
            if ( ! c || ! c->isA<Statement>() )
                continue;

            auto cc = get_or_add_node(c);

            add_edge(parent, cc);

            auto x = add_block(parent, c->children(), *c);

            // We might have added a dead edge to a `ScopeEnd` with
            // `add_block`, clean it up again.
            if ( x && x->getData()->isA<ScopeEnd>() ) {
                remove_node(x);
            }

            parent = std::move(cc);
        }
    }

    // Add unreachable flows.
    if ( has_dead_flow && last != stmts.end() ) {
        auto next = add_block(nullptr, Nodes{last, stmts.end()}, scope);
        auto mix = get_or_add_node(create_meta_node<Flow>());
        add_edge(parent, mix);
        add_edge(next, mix);
        parent = std::move(mix);
    }

    // Connect the scope end to prevent leaking of locals out of their blocks.
    add_edge(parent, scope_end);
    parent = std::move(scope_end);

    return parent;
}

CFG::NodeP CFG::add_for(NodeP parent, const statement::For& for_) {
    auto&& sequence = get_or_add_node(for_.sequence());
    add_edge(std::move(parent), sequence);

    auto&& local = get_or_add_node(for_.local());
    add_edge(sequence, local);

    auto body_end = add_block(std::move(local), for_.body()->children(), *for_.body());
    add_edge(body_end, sequence);

    return sequence;
}

CFG::NodeP CFG::add_while(NodeP parent, const statement::While& while_) {
    if ( auto* init = while_.init() ) {
        auto init_ = get_or_add_node(init);
        add_edge(std::move(parent), init_);
        parent = std::move(init_);
    }

    auto&& condition = get_or_add_node(while_.condition());
    add_edge(std::move(parent), condition);

    auto body_end = add_block(condition, while_.body()->children(), *while_.body());
    add_edge(body_end, condition);

    auto mix = get_or_add_node(create_meta_node<Flow>());
    add_edge(condition, mix);

    if ( auto&& else_ = while_.else_() ) {
        auto&& else_end = add_block(condition, else_->children(), *else_);
        add_edge(else_end, mix);
    }

    return mix;
}

CFG::NodeP CFG::add_if(NodeP parent, const statement::If& if_) {
    if ( auto* init = if_.init() ) {
        auto init_ = get_or_add_node(init);
        add_edge(std::move(parent), init_);
        parent = std::move(init_);
    }

    auto&& condition = get_or_add_node(if_.condition());
    add_edge(std::move(parent), condition);

    auto mix = get_or_add_node(create_meta_node<Flow>());
    auto true_end = add_block(condition, if_.true_()->children(), *if_.true_());

    add_edge(true_end, mix);

    if ( auto* false_ = if_.false_() ) {
        auto false_end = add_block(condition, false_->children(), *false_);
        add_edge(false_end, mix);
    }

    else
        add_edge(condition, mix);

    return mix;
}

CFG::NodeP CFG::add_try_catch(const NodeP& parent, const statement::Try& try_catch) {
    auto try_ = add_block(parent, try_catch.body()->children(), *try_catch.body());

    // Connect into node combining flows from `try` and `catch` blocks.
    auto mix_after = get_or_add_node(create_meta_node<Flow>());
    add_edge(try_, mix_after);

    // Since the `try` block can throw connect into node flowing into all `catch` blocks.
    auto mix_into_catches = get_or_add_node(create_meta_node<Flow>());
    add_edge(try_, mix_into_catches);

    for ( auto&& catch_ : try_catch.catches() ) {
        auto catch_end = add_block(mix_into_catches, catch_->body()->children(), *catch_);

        add_edge(catch_end, mix_after);
    }

    return mix_after;
}

CFG::NodeP CFG::add_return(const NodeP& parent, const N& expression) {
    if ( expression ) {
        // We store the return statement to make us of it in data flow analysis.
        auto r = get_or_add_node(expression->parent());
        add_edge(parent, r);
        add_edge(r, end);
        return end;
    }

    return parent;
}

CFG::NodeP CFG::add_throw(NodeP parent, const N& expression, const NodeP& scope_end) {
    auto expr = get_or_add_node(expression);

    add_edge(std::move(parent), expr);
    add_edge(expr, scope_end);

    return scope_end;
}

CFG::NodeP CFG::add_call(NodeP parent, operator_::function::Call* call) {
    auto c = get_or_add_node(call);
    add_edge(std::move(parent), c);
    return c;
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

    // The end node does not have outgoing edges.
    if ( from == end )
        return;

    if ( const auto& xs = outEdges(g, from.get());
         xs.end() != std::find_if(xs.begin(), xs.end(), [&](const auto& e) { return e->getNodePair().second == to; }) )
        return;
    else {
        auto e =
            std::make_shared<CXXGraph::DirectedEdge<CFG::N>>(g.getEdgeSet().size(), std::move(from), std::move(to));
        g.addEdge(std::move(e));
        return;
    }
}

void CFG::remove_node(const NodeP& n) {
    assert(outEdges(g, n.get()).empty());

    for ( auto&& edge : inEdges(g, n.get()) )
        g.removeEdge(edge->getId());

    g.removeNode(n->getUserId());
}

std::string CFG::dot() const {
    std::stringstream ss;

    ss << "digraph {\n";

    std::unordered_map<CXXGraph::id_t, size_t> node_ids; // Deterministic node ids.

    const auto& nodes = g.getNodeSet();
    auto sorted_nodes = std::vector(nodes.begin(), nodes.end());
    std::sort(sorted_nodes.begin(), sorted_nodes.end(),
              [](const auto& a, const auto& b) { return *a->getData() < *b->getData(); });

    auto escape = [](std::string_view s) { return rt::escapeUTF8(s, rt::render_style::UTF8::EscapeQuotes); };

    for ( auto&& n : sorted_nodes ) {
        auto id = node_ids.size();
        node_ids.insert({n->getId(), id});

        auto&& data = n->getData();

        std::optional<std::string> xlabel;
        if ( auto it = dataflow.find(n.get()); it != dataflow.end() ) {
            const auto& transfer = it->second;

            auto use = [&]() {
                auto xs = util::transformToVector(transfer.use, [&](auto* decl) {
                    return escape(decl->template as<const Declaration>()->id());
                });
                std::sort(xs.begin(), xs.end());
                if ( ! xs.empty() )
                    return util::fmt("use: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto gen = [&]() {
                auto xs = util::transformToVector(transfer.gen, [&](auto&& kv) {
                    auto&& [decl, node] = kv;
                    return util::fmt("%s: %s", escape(decl->template as<const hilti::Declaration>()->id()),
                                     escape(node->getData()->print()));
                });
                std::sort(xs.begin(), xs.end());
                if ( ! xs.empty() )
                    return util::fmt("gen: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto kill = [&]() {
                auto xs = util::transformToVector(transfer.kill, [&](auto&& kv) {
                    auto&& decl = kv.first;
                    auto&& nodes = kv.second;

                    return util::fmt("%s: [%s]", escape(decl->template as<const hilti::Declaration>()->id()),
                                     util::join(util::filter(
                                                    [&]() {
                                                        auto xs = util::transformToVector(nodes, [&](auto&& x) {
                                                            return escape(x->getData()->print());
                                                        });

                                                        std::sort(xs.begin(), xs.end());
                                                        return xs;
                                                    }(),
                                                    [](auto&& x) { return ! x.empty(); }),
                                                ", "));
                });
                std::sort(xs.begin(), xs.end());
                if ( ! xs.empty() )
                    return util::fmt("kill: [%s]", util::join(xs, " "));
                else
                    return std::string();
            }();

            auto reachability = [&]() -> std::string {
                auto&& r = transfer.reachability;
                if ( ! r )
                    return "";

                auto to_str = [&](auto&& xs) {
                    auto ys = util::transformToVector(xs, [&](auto&& x) { return escape(x->getData()->print()); });
                    std::sort(ys.begin(), ys.end());
                    return util::join(ys, ", ");
                };

                return util::fmt("reach: { in: [%s] out: [%s] }", to_str(r->in), to_str(r->out));
            }();

            auto aliases = [&]() {
                auto xs = util::transformToVector(transfer.aliases, [&](auto* decl) {
                    return escape(decl->template as<const hilti::Declaration>()->id());
                });
                std::sort(xs.begin(), xs.end());
                if ( ! xs.empty() )
                    return util::fmt("aliases: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto keep = [&]() -> std::string { return transfer.keep ? "keep" : ""; }();

            xlabel = util::fmt("xlabel=\"%s\"",
                               util::join(util::filter(std::vector{use, gen, kill, reachability, aliases, keep},
                                                       [](auto&& x) { return ! x.empty(); }),
                                          " "));
        }

        if ( auto&& meta = data->tryAs<MetaNode>() ) {
            if ( data->isA<Start>() )
                ss << util::fmt("    %s [label=start shape=Mdiamond %s];\n", id, xlabel ? *xlabel : "");

            else if ( data->isA<End>() )
                ss << util::fmt("    %s [label=end shape=Msquare %s];\n", id, xlabel ? *xlabel : "");

            else if ( data->isA<Flow>() )
                ss << util::fmt("    %s [shape=point %s];\n", id, xlabel ? *xlabel : "");

            else if ( auto* scope = data->tryAs<ScopeEnd>() ) {
                ss << util::fmt("    %s [label=\"scope_end %s\" shape=triangle %s];\n", id,
                                scope->scope->meta().location(), xlabel ? *xlabel : "");
            }

            else
                util::cannotBeReached();
        }

        else {
            ss << util::fmt("    %s [label=\"%s\" %s];\n", id, escape(data->print()), xlabel ? *xlabel : "");
        }
    }

    const auto& edges = g.getEdgeSet();
    auto sorted_edges = std::vector(edges.begin(), edges.end());
    std::sort(sorted_edges.begin(), sorted_edges.end(), [](const auto& a, const auto& b) {
        // Edges have deterministic IDs derived from the insertion order.
        return a->getId() < b->getId();
    });

    for ( auto&& e : sorted_edges ) {
        auto&& [from, to] = e->getNodePair();
        ss << util::fmt("    %s -> %s [label=\"%s\"];\n", node_ids.at(from->getId()), node_ids.at(to->getId()),
                        e->getId());
    }

    ss << "}";

    return ss.str();
}

CXXGraph::T_NodeSet<CFG::N> CFG::unreachable_nodes() const {
    auto xs = nodes();

    CXXGraph::T_NodeSet<N> result;
    for ( auto&& n : xs ) {
        auto&& data = n->getData();
        if ( data && ! data->isA<MetaNode>() && inEdges(g, n.get()).empty() )
            result.insert(n);
    }

    return result;
}

struct DataflowVisitor : visitor::PreOrder {
    DataflowVisitor(const CXXGraph::Node<CFG::N>* root_) : root(root_) {}

    const CXXGraph::Node<CFG::N>* root = nullptr;
    Transfer transfer;

    void operator()(statement::Assert*) override { transfer.keep = true; }
    void operator()(statement::Comment*) override { transfer.keep = true; }
    void operator()(statement::SetLocation*) override { transfer.keep = true; }
    void operator()(statement::Throw*) override { transfer.keep = true; }
    void operator()(statement::Return*) override { transfer.keep = true; }
    void operator()(statement::Yield*) override { transfer.keep = true; }

    void operator()(operator_::function::Call* call) override {
        auto* fun = call->op0()->as<expression::Name>();
        auto* decl = fun->resolvedDeclaration();
        assert(decl); // Input should be fully resolved.

        const auto& formal_args = decl->as<declaration::Function>()->function()->ftype()->parameters();

        const auto& args = call->op1()->as<expression::Ctor>()->ctor()->as<ctor::Tuple>()->value();
        assert(args.size() == formal_args.size()); // The call should match the signature.

        for ( size_t i = 0; i < formal_args.size(); ++i ) {
            auto&& formal_arg = formal_args[i];
            auto&& arg = args[i];

            switch ( formal_arg->kind() ) {
                case parameter::Kind::Unknown: [[fallthrough]];
                case parameter::Kind::Copy: [[fallthrough]];
                case parameter::Kind::In: break;

                case parameter::Kind::InOut: {
                    auto* name = arg->tryAs<expression::Name>();
                    if ( ! name )
                        break;

                    auto* decl = name->resolvedDeclaration();
                    if ( ! decl )
                        break;

                    transfer.gen[decl] = root;
                    break;
                };
            };
        }

        // Since we do not know whether the called function is pure always keep it.
        // TODO(bbannier): remove calls to pure functions.
        transfer.keep = true;
    }

    void operator()(Expression* expression) override {
        // If the top-level CFG node is an expression we are looking at an expression for control flow -- keep it.
        if ( expression == root->getData() )
            transfer.keep = true;
    }

    void operator()(expression::Name* name) override {
        auto* decl = name->resolvedDeclaration();
        if ( ! decl )
            return;

        auto* stmt = root->getData();
        // If the statement was a simple `Expression` unwrap it to get the more specific node.
        if ( stmt->isA<statement::Expression>() ) {
            if ( auto* child = stmt->child(0) )
                stmt = child;
        }

        if ( auto* assign = stmt->tryAs<expression::Assign>() ) {
            // Figure out which side of the assignment this name is on.
            auto side = std::optional<Side>();
            Node* x = name;
            do {
                if ( x == assign->target() ) {
                    side = Side::LHS;
                    break;
                }

                if ( x == assign->source() ) {
                    side = Side::RHS;
                    break;
                }

                x = x->parent();
            } while ( x && x != root->getData() );
            assert(side);

            // A use on either side uses the declaration.
            transfer.use.insert(decl);

            // A LHS use generates a new value.
            if ( side == Side::LHS )
                transfer.gen[decl] = root;
        }

        else if ( stmt->isA<statement::Declaration>() )
            // Names in declaration statements appear on the RHS.
            transfer.use.insert(decl);

        else if ( auto* global = stmt->tryAs<declaration::GlobalVariable>() ) {
            // Names in the global declaration appear on the RHS.
            transfer.use.insert(decl);

            // FIXME(bbannier): handle local declarations as well?

            if ( auto* type = global->type()->type() ) {
                if ( is_aliasing_type(*type) )
                    transfer.aliases.insert(decl);
            }
        }

        else if ( stmt->isA<statement::Return>() )
            // Simply flows a value but does not generate or kill any.
            transfer.use.insert(decl);

        else {
            // All other nodes use the current decl, and are marked as unremovable.
            transfer.keep = true;
            transfer.use.insert(decl);
        }
    }

    void operator()(statement::Declaration* x) override { transfer.gen[x->declaration()] = root; }

    void operator()(declaration::GlobalVariable* x) override { transfer.gen[x] = root; }

    void operator()(declaration::LocalVariable* x) override {
        transfer.gen[x] = root;

        // Keep locals of struct types with finalizer since it might have side effects.
        //
        // TODO(bbannier): Consider dropping even these if we can prove that
        // the finalizer has no side effects.
        if ( auto* s = x->type()->type()->tryAs<type::Struct>(); s && s->field("~finally") )
            transfer.keep = true;
    }
};

void CFG::populate_dataflow() {
    auto visit_node = [](const CXXGraph::Node<N>* n) -> Transfer {
        if ( n->getData()->isA<MetaNode>() )
            return {};

        auto v = DataflowVisitor(n);
        visitor::visit(v, n->getData());

        return std::move(v.transfer);
    };

    // Populate uses and the gen sets.
    for ( auto&& n : g.getNodeSet() ) {
        if ( n->getData() )
            dataflow[n.get()] = visit_node(n.get());
    }

    { // Encode aliasing information.

        auto find_node = [&](const hilti::Node* const n) -> const CXXGraph::Node<N>* {
            // Cache to prevent repeatedly computing graph node ID.
            std::map<decltype(n), std::string> id_cache;
            std::string* id = nullptr;
            if ( auto it = id_cache.find(n); it != id_cache.end() )
                id = &it->second;
            else {
                auto id_ = node_id(n);
                auto [i, _] = id_cache.insert({n, id_});
                id = &i->second;
            }
            assert(id);

            auto x = g.getNode(*id);
            if ( x )
                return x.value().get();

            return nullptr;
        };

        // First make aliasing symmetric: to handle the case of e.g.,
        // references aliasing is stored symmetrically, i.e., if `a` aliases
        // `b`, `b` will also alias `a`.
        for ( auto&& [n, transfer] : dataflow ) {
            for ( const auto* alias : transfer.aliases ) {
                const auto* stmt = find_node(alias);
                if ( ! stmt || ! dataflow.count(stmt) ) {
                    // Could not find node declaring aliased name.
                    util::detail::internalError(util::fmt(R"(could not find CFG node for "%s" aliased in "%s")",
                                                          alias->print(), n->getData()->print()));
                    continue;
                }

                dataflow.at(stmt).aliases.insert(n->getData());
            }
        }

        // Now mark aliased nodes as used.
        for ( auto&& [n, transfer] : dataflow ) {
            for ( const auto* use : transfer.use ) {
                const auto* stmt = find_node(use);
                if ( ! stmt || ! dataflow.count(stmt) )
                    continue;

                for ( const auto* alias : dataflow.at(stmt).aliases )
                    transfer.use.insert(alias);
            }
        }
    }

    { // Populate the kill sets.
        std::map<const Node*, std::unordered_set<const CXXGraph::Node<Node*>*>> gens;
        for ( auto&& [_, transfer] : dataflow ) {
            for ( auto&& [d, n] : transfer.gen )
                gens[d].insert(n);
        }

        for ( auto&& n : g.getNodeSet() ) {
            auto& transfer = dataflow[n.get()];

            for ( auto&& [d, ns] : gens ) {
                auto x = transfer.gen.find(d);
                // Only kill gens also generated in this node.
                if ( x == transfer.gen.end() )
                    continue;

                for ( auto&& nn : ns ) {
                    // Do not kill the gen in this node.
                    if ( x->second != nn )
                        transfer.kill[d].insert(nn);
                }
            }
        }
    }
}

void CFG::populate_reachable_expressions() {
    if ( dataflow.empty() )
        populate_dataflow();

    auto nodes = g.getNodeSet();

    // Reset reachability information.
    for ( auto&& n : nodes ) {
        dataflow.at(n.get()).reachability = Reachability();
    }

    // Compute in and out sets for each node.
    while ( true ) {
        bool changed = false;

        for ( const auto& n : nodes ) {
            auto* data = n->getData();
            if ( ! data )
                continue;

            auto& reachability = dataflow[n.get()].reachability;
            auto& in = reachability->in;
            auto& out = reachability->out;

            auto* scope_end = data->tryAs<ScopeEnd>();

            // The in set is the union of all incoming nodes.
            for ( const auto& e : inEdges(g, n.get()) ) {
                const auto& [from, _] = e->getNodePair();

                const auto& from_ = dataflow.at(from.get()).reachability->out; // Must already exist.

                for ( auto&& f : from_ ) {
                    // Prevent leaking of locals out of their scope.
                    //
                    // At the end of scopes (currently: blocks) we insert a `ScopeEnd` node. Most locals must not flow
                    // out of this node, we however allow locals flowing from `return` statements to precede.
                    if ( scope_end ) {
                        assert(dataflow.count(f));
                        const auto& transfer = dataflow[f];

                        // Updates to declarations local to the block must not propagate out.
                        bool is_local_only = std::all_of(transfer.gen.begin(), transfer.gen.end(), [&](auto&& g) {
                            auto&& [decl, n] = g;
                            assert(decl->template isA<Declaration>());
                            return contains(*scope_end->scope, *decl);
                        });

                        if ( is_local_only )
                            continue;
                    }

                    auto [_, inserted] = in.insert(f);
                    changed |= inserted;
                }
            }

            // The out set of a node is gen + (in - kill)
            const auto& gen = dataflow.at(n.get()).gen;
            const auto& kill = dataflow.at(n.get()).kill;

            for ( auto&& [decl, g] : gen ) {
                auto [_, inserted] = out.insert(g);
                changed |= inserted;
            }

            for ( auto&& i : in ) {
                if ( std::any_of(kill.begin(), kill.end(), [&](auto&& kv) {
                         auto&& [_k, n] = kv;
                         return n.count(i);
                     }) )
                    continue;

                auto [_, inserted] = out.insert(i);
                changed |= inserted;
            }
        }

        if ( ! changed )
            break;
    }
}

std::vector<const CXXGraph::Node<CFG::N>*> CFG::unreachable_statements() const {
    // This can only be called after reachability information has been populated.
    assert(! dataflow.empty());
    assert(dataflow.begin()->second.reachability);

    std::map<const CXXGraph::Node<N>*, uint64_t> uses;

    // Loop over all nodes.
    for ( const auto& [n, transfer] : dataflow ) {
        if ( ! n || ! n->getData() )
            continue;

        // Check whether we want to declare any of the statements used. We currently do this for
        // - `inout` parameters since their result is can be seen after the function has ended,
        // - globals since they could be used elsewhere without us being able to see it,
        // - `self` expression since they live on beyond the current block.
        if ( n->getData()->isA<End>() ) {
            assert(dataflow.count(n));
            // If we saw an operation an `inout` parameter at the end of the flow, mark the parameter as used.
            // For each incoming statement ...
            for ( auto&& in : transfer.reachability->in ) {
                assert(dataflow.count(in));
                // If the statement generated an update to the value ...
                for ( auto&& [n_, _] : dataflow.at(in).gen ) {
                    if ( n_->isA<declaration::GlobalVariable>() )
                        ++uses[in];

                    else if ( auto&& p = n_->tryAs<declaration::Parameter>();
                              p && p->kind() == parameter::Kind::InOut ) {
                        ++uses[in];
                    }

                    else if ( const auto* expr = n_->tryAs<declaration::Expression>() ) {
                        if ( auto* keyword = expr->expression()->tryAs<expression::Keyword>();
                             keyword && keyword->kind() == expression::keyword::Kind::Self )
                            ++uses[in];
                    }
                }
            }
        }

        if ( ! n->getData()->isA<MetaNode>() )
            (void)uses[n]; // Record statement if not already known.

        // For each update to a declaration generated by a node ...
        for ( auto&& [decl, node] : transfer.gen ) {
            // Search for nodes making use of the statement.
            for ( auto&& [n_, t] : dataflow ) {
                // First filter by nodes using the decl.
                if ( ! t.use.count(decl) )
                    continue;

                // If an update is used and in the `in` set of a node it is used.
                auto&& in_ = t.reachability->in;
                if ( in_.find(node) != in_.end() )
                    ++uses[n];
            }
        }
    }

    std::vector<const CXXGraph::Node<CFG::N>*> result;
    for ( auto&& [n, uses] : uses ) {
        if ( uses > 0 )
            continue;

        if ( dataflow.at(n).keep )
            continue;

        result.push_back(n);
    }

    return result;
}

} // namespace detail::cfg

} // namespace hilti
