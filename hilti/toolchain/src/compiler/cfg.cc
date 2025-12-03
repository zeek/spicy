// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/cfg.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <iterator>
#include <map>
#include <optional>
#include <ranges>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <hilti/rt/util.h>

#include <hilti/ast/attribute.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/declarations/expression.h>
#include <hilti/ast/declarations/field.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/global-variable.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/declarations/parameter.h>
#include <hilti/ast/declarations/type.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/expressions/assign.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/expressions/keyword.h>
#include <hilti/ast/expressions/logical-and.h>
#include <hilti/ast/expressions/logical-not.h>
#include <hilti/ast/expressions/logical-or.h>
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/resolved-operator.h>
#include <hilti/ast/function.h>
#include <hilti/ast/location.h>
#include <hilti/ast/node.h>
#include <hilti/ast/operator.h>
#include <hilti/ast/operators/function.h>
#include <hilti/ast/operators/struct.h>
#include <hilti/ast/scope-lookup.h>
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
#include <hilti/ast/statements/switch.h>
#include <hilti/ast/statements/throw.h>
#include <hilti/ast/statements/try.h>
#include <hilti/ast/statements/while.h>
#include <hilti/ast/statements/yield.h>
#include <hilti/ast/type.h>
#include <hilti/ast/types/reference.h>
#include <hilti/ast/types/struct.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/util.h>
#include <hilti/hilti/ast/types/bytes.h>
#include <hilti/hilti/ast/types/list.h>
#include <hilti/hilti/ast/types/map.h>
#include <hilti/hilti/ast/types/set.h>
#include <hilti/hilti/ast/types/stream.h>
#include <hilti/hilti/ast/types/vector.h>

namespace hilti::detail::cfg {

std::deque<GraphNode> CFG::postorder() const {
    std::deque<GraphNode> sorted;

    std::unordered_set<NodeId> visited;

    std::function<void(NodeId)> dfs_visit = [&](NodeId node_id) {
        if ( visited.contains(node_id) )
            return;

        visited.insert(node_id);

        for ( const auto& neighbor_id : _graph.neighborsDownstream(node_id) )
            dfs_visit(neighbor_id);

        const auto* node = _graph.getNode(node_id);
        assert(node);
        sorted.push_back(*node);
    };

    // This will sort all reachable nodes.
    dfs_visit(_begin->identity());

    return sorted;
}

// Helper function to check whether some `inner` node is a child of an `outer` node.
static bool contains(const Node& outer, const Node& inner) {
    const auto* n = &inner;

    do {
        if ( n == &outer )
            return true;
        n = n->parent();
    } while ( n );

    return false;
}

CFG::CFG(const Node* root)
    : _begin(_getOrAddNode(_createMetaNode<Start>())), _end(_getOrAddNode(_createMetaNode<End>(root))) {
    assert(root && root->isA<statement::Block>() && "only building from blocks currently supported");

    _begin = _addGlobals(_begin, *root);
    _begin = _addParameters(_begin, *root);

    auto last = _addBlock(_begin, root->children(), root);
    if ( last != _end )
        _addEdge(last, _end);

    // Clean up artifacts from CFG construction.
    //
    // - `End` nodes with no incoming edges. These can arise if blocks never
    //   flow through their end node, e.g., due to early return.
    while ( true ) {
        std::set<uintptr_t> dead_ends;

        for ( const auto& [id, n] : _graph.nodes() ) {
            if ( n->isA<End>() && _graph.neighborsUpstream(id).empty() )
                dead_ends.insert(id);
        }

        for ( const auto& id : dead_ends )
            _graph.removeNode(id);

        if ( dead_ends.empty() )
            break;
    }

    _populateDataflow();
}

GraphNode CFG::_addGlobals(GraphNode predecessor, const Node& root) {
    auto* p = root.parent();
    if ( ! p )
        return predecessor;

    auto* mod = p->tryAs<declaration::Module>();
    if ( ! mod )
        return predecessor;

    // A global variables with an init statement since they are effectively statements.
    for ( auto* decl : mod->declarations() ) {
        auto* global = decl->tryAs<declaration::GlobalVariable>();
        if ( ! global )
            continue;

        auto stmt = _getOrAddNode(global);
        _addEdge(predecessor, stmt);
        predecessor = stmt;
    }

    return predecessor;
}

GraphNode CFG::_addParameters(GraphNode predecessor, const Node& root) {
    auto* p = root.parent();
    if ( ! p )
        return predecessor;

    auto* fn = p->tryAs<Function>();
    if ( ! fn )
        return predecessor;

    // Add parameters.
    for ( auto* param : fn->ftype()->parameters() ) {
        if ( ! param )
            continue;

        auto d = _getOrAddNode(param);
        _addEdge(predecessor, d);
        predecessor = d;
    }

    switch ( fn->ftype()->flavor() ) {
        case type::function::Flavor::Method: {
            auto type_name = fn->id().namespace_();
            assert(! type_name.empty());

            auto lookup = scope::lookupID<declaration::Type>(type_name, p, "type");
            if ( ! lookup )
                util::detail::internalError(
                    util::fmt("could not find type '%s' for method/hook '%s'", type_name, fn->id()));

            const auto& [decl, id] = *lookup;

            if ( auto* struct_ = decl->type()->type()->tryAs<type::Struct>() ) {
                // Add implicit `self` parameter for methods.
                auto d = _getOrAddNode(struct_->self());
                _addEdge(predecessor, d);
                predecessor = d;

                // Add unit parameters which are implicitly in scope.
                for ( auto* p : struct_->parameters() ) {
                    auto n = _getOrAddNode(p);
                    _addEdge(predecessor, n);
                    predecessor = n;
                }
            }

            break;
        }

        case type::function::Flavor::Hook: [[fallthrough]];
        case type::function::Flavor::Function: {
            break; // Nothing.
        }
    }

    return predecessor;
}

GraphNode CFG::_addBlock(GraphNode predecessor, const Nodes& stmts, const Node* scope) {
    // If `children` directly has any statements which change control flow like
    // `throw` or `return` any statements after that are unreachable. To model
    // such ASTs we add a flow with all statements up to the "last" semantic
    // statement (either the last child or the control flow statement) to the
    // CFG under `parent`. Statements after that are added as children without
    // parents, and mixed with the previous flow.

    // After this block `last` is the last reachable statement, either end of
    // children or a control flow statement.
    auto last = std::ranges::find_if(stmts, [](auto* c) {
        return c && (c->template isA<statement::Return>() || c->template isA<statement::Throw>() ||
                     c->template isA<statement::Continue>() || c->template isA<statement::Break>());
    });
    const bool has_dead_flow = last != stmts.end();
    if ( has_dead_flow )
        last = std::next(last);

    // Node this block will eventually flow into.
    auto scope_end = _getOrAddNode(_createMetaNode<End>(scope));

    // Add all statements which are part of the normal flow.
    for ( auto* c : (last != stmts.end() ? Nodes(stmts.begin(), last) : stmts) ) {
        if ( ! c )
            continue;

        if ( auto* while_ = c->tryAs<statement::While>() )
            predecessor = _addWhile(predecessor, *while_, scope_end);

        else if ( auto* for_ = c->tryAs<statement::For>() )
            predecessor = _addFor(predecessor, *for_);

        else if ( auto* if_ = c->tryAs<statement::If>() )
            predecessor = _addIf(predecessor, *if_);

        else if ( auto* switch_ = c->tryAs<statement::Switch>() )
            predecessor = _addSwitch(predecessor, *switch_);

        else if ( auto* try_catch = c->tryAs<statement::Try>() )
            predecessor = _addTryCatch(predecessor, *try_catch);

        else if ( auto* throw_ = c->tryAs<statement::Throw>() )
            predecessor = _addThrow(predecessor, *throw_, scope_end);

        else if ( auto* return_ = c->tryAs<statement::Return>() )
            predecessor = _addReturn(predecessor, *return_);

        else if ( c->isA<statement::Continue>() || c->isA<statement::Break>() )
            // `continue`/`break` statements only add flow, but no data.
            ; // Nothing.

        else if ( auto* call = c->tryAs<operator_::function::Call>() )
            predecessor = _addCall(predecessor, *call);

        else if ( auto* block = c->tryAs<statement::Block>() )
            predecessor = _addBlock(predecessor, block->statements(), block);

        else if ( auto* expr = c->tryAs<statement::Expression>() ) {
            auto n = _getOrAddNode(expr);
            _addEdge(predecessor, n);
            predecessor = n;
        }

        else if ( auto* stmt = c->tryAs_<Statement>() ) {
            GraphNode cc;

            if ( auto* decl = stmt->tryAs<statement::Declaration>() )
                // Store the declaration instead of the full statement so we
                // can refer to it from parts working with declarations.
                cc = _getOrAddNode(decl->declaration());

            else
                cc = _getOrAddNode(stmt);

            _addEdge(predecessor, cc);

            auto x = _addBlock(predecessor, stmt->children(), stmt);

            // We might have added a dead edge to a `ScopeEnd` with
            // `add_block`, clean it up again.
            if ( x.value() && x->isA<End>() )
                _graph.removeNode(x->identity());

            predecessor = cc;
        }
    }

    // Add unreachable flows.
    if ( has_dead_flow && last != stmts.end() ) {
        auto next = _addBlock(GraphNode(), Nodes{last, stmts.end()}, scope);
        auto mix = _getOrAddNode(_createMetaNode<Flow>());
        _addEdge(predecessor, mix);
        _addEdge(next, mix);
        predecessor = mix;
    }

    // Connect the scope end to prevent leaking of locals out of their blocks.
    _addEdge(predecessor, scope_end);
    predecessor = scope_end;

    return predecessor;
}

GraphNode CFG::_addFor(GraphNode predecessor, const statement::For& for_) {
    const auto& sequence = _getOrAddNode(for_.sequence());
    _addEdge(predecessor, sequence);

    const auto& local = _getOrAddNode(for_.local());
    _addEdge(sequence, local);

    auto body_end = _addBlock(local, for_.body()->children(), for_.body());
    _addEdge(body_end, sequence);

    auto scope_end = _getOrAddNode(_createMetaNode<End>(&for_));
    _addEdge(sequence, scope_end);

    return scope_end;
}

GraphNode CFG::_addWhile(GraphNode predecessor, const statement::While& while_, GraphNode scope_end) {
    if ( auto* init = while_.init() ) {
        auto init_ = _getOrAddNode(init);
        _addEdge(predecessor, init_);
        _addEdge(init_, scope_end);

        predecessor = init_;
    }

    if ( auto* c = while_.condition() ) {
        const auto& condition = _getOrAddNode(c);
        _addEdge(predecessor, condition);
        predecessor = condition;
    }

    auto body_end = _addBlock(predecessor, while_.body()->children(), while_.body());
    _addEdge(body_end, predecessor);

    auto mix = _getOrAddNode(_createMetaNode<Flow>());
    _addEdge(predecessor, mix);

    if ( auto* else_ = while_.else_() ) {
        const auto& else_end = _addBlock(predecessor, else_->children(), else_);
        _addEdge(else_end, mix);
    }

    return mix;
}

GraphNode CFG::_addIf(GraphNode predecessor, const statement::If& if_) {
    if ( auto* init = if_.init() ) {
        auto init_ = _getOrAddNode(init);
        _addEdge(predecessor, init_);
        predecessor = init_;
    }

    const auto& condition = _getOrAddNode(if_.condition());
    _addEdge(predecessor, condition);

    auto mix = _getOrAddNode(_createMetaNode<Flow>());
    auto true_end = _addBlock(condition, if_.true_()->children(), if_.true_());

    _addEdge(true_end, mix);

    if ( auto* false_ = if_.false_() ) {
        auto false_end = _addBlock(condition, false_->children(), false_);
        _addEdge(false_end, mix);
    }

    else
        _addEdge(condition, mix);

    return mix;
}

GraphNode CFG::_addTryCatch(GraphNode predecessor, const statement::Try& try_catch) {
    auto try_ = _addBlock(predecessor, try_catch.body()->children(), try_catch.body());

    // Connect into node combining flows from `try` and `catch` blocks.
    auto mix_after = _getOrAddNode(_createMetaNode<Flow>());
    _addEdge(try_, mix_after);

    // Since the `try` block can throw connect into node flowing into all `catch` blocks.
    auto mix_into_catches = _getOrAddNode(_createMetaNode<Flow>());
    _addEdge(try_, mix_into_catches);

    for ( auto* catch_ : try_catch.catches() ) {
        auto catch_end = _addBlock(mix_into_catches, catch_->body()->children(), catch_);

        _addEdge(catch_end, mix_after);
    }

    return mix_after;
}

GraphNode CFG::_addSwitch(GraphNode predecessor, const statement::Switch& switch_) {
    const auto& condition = _getOrAddNode(switch_.condition());
    _addEdge(predecessor, condition);

    auto mix = _getOrAddNode(_createMetaNode<Flow>());

    if ( ! switch_.default_() )
        _addEdge(condition, mix);

    for ( auto* case_ : switch_.cases() ) {
        GraphNode case_block;

        // We work on the preprocessed expressions so we can properly
        // access e.g., reads of the switch condition.
        const auto expressions = case_->preprocessedExpressions();

        if ( ! expressions.empty() ) {
            auto mix_expr = _getOrAddNode(_createMetaNode<Flow>());

            for ( auto* x : expressions ) {
                auto g = _getOrAddNode(x);
                _addEdge(condition, g);
                _addEdge(g, mix_expr);
            }

            case_block = _addBlock(mix_expr, case_->body()->children(), case_->body());
        }

        else
            case_block = _addBlock(condition, case_->body()->children(), case_->body());

        _addEdge(case_block, mix);
    }

    return mix;
}

GraphNode CFG::_addReturn(GraphNode predecessor, const statement::Return& return_) {
    auto r = _getOrAddNode(const_cast<statement::Return*>(&return_));
    _addEdge(predecessor, r);
    _addEdge(r, _end);

    return _end;
}

GraphNode CFG::_addThrow(GraphNode predecessor, statement::Throw& throw_, GraphNode scope_end) {
    if ( auto* expression = throw_.expression() ) {
        auto expr = _getOrAddNode(expression);

        _addEdge(predecessor, expr);
        _addEdge(expr, scope_end);
    }
    else
        _addEdge(predecessor, scope_end);

    return scope_end;
}

GraphNode CFG::_addCall(GraphNode predecessor, operator_::function::Call& call) {
    auto c = _getOrAddNode(&call);
    _addEdge(predecessor, c);
    return c;
}

GraphNode CFG::_getOrAddNode(GraphNode n) {
    if ( const auto* x = _graph.getNode(n->identity()) )
        return *x;

    _graph.addNode(n, n->identity());
    return n;
}

void CFG::_addEdge(const GraphNode& from, const GraphNode& to) {
    if ( ! from.value() || ! to.value() )
        return;

    // The end node does not have outgoing edges.
    if ( from == _end )
        return;

    if ( const auto& xs = _graph.neighborsDownstream(from->identity());
         xs.end() != std::ranges::find_if(xs, [&](const auto& t) { return t == to->identity(); }) )
        return;
    else {
        _graph.addEdge(from->identity(), to->identity());
        return;
    }
}

void detail::cfg::CFG::removeNode(Node* node) {
    auto id = node->identity();

    const auto& out = _graph.neighborsDownstream(id);
    const auto& in = _graph.neighborsUpstream(id);

    // Create new edges between incoming and outgoing nodes.
    for ( const auto& i : in ) {
        for ( const auto& o : out )
            _graph.addEdge(i, o);
    }

    _graph.removeNode(id);
}

std::string CFG::dot(bool omit_dataflow) const {
    std::stringstream ss;

    ss << "digraph {\n";

    std::unordered_map<uintptr_t, size_t> node_ids; // Deterministic node ids.

    std::vector<GraphNode> sorted_nodes;
    std::transform(_graph.nodes().begin(), _graph.nodes().end(), std::back_inserter(sorted_nodes),
                   [](const auto& p) { return p.second; });
    std::ranges::sort(sorted_nodes, [](const GraphNode& a, const GraphNode& b) {
        return a.value() && b.value() && a->identity() < b->identity();
    });

    auto escape = [](std::string_view s) { return rt::escapeUTF8(s, rt::render_style::UTF8::EscapeQuotes); };

    for ( const auto& n : sorted_nodes ) {
        auto id = node_ids.size();
        node_ids.insert({n->identity(), id});

        std::optional<std::string> xlabel;
        if ( auto it = _dataflow.find(n); ! omit_dataflow && it != _dataflow.end() ) {
            const auto& transfer = it->second;

            auto read = [&]() {
                auto xs = util::toVector(transfer.read |
                                         std::views::transform([&](auto* decl) { return escape(decl->id()); }));
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("read: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto write = [&]() {
                auto xs = util::toVector(transfer.write |
                                         std::views::transform([&](auto* decl) { return escape(decl->id()); }));
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("write: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto gen = [&]() {
                auto xs = util::toVector(transfer.gen | std::views::transform([&](const auto& kv) {
                                             const auto& [decl, node] = kv;
                                             return util::fmt("%s: %s", escape(decl->id()), escape(node->print()));
                                         }));
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("gen: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto to_str = [&](const auto& xs) {
                std::vector<std::string> ys;
                for ( const auto& [decl, stmts] : xs ) {
                    std::vector<std::string> xs;
                    for ( const auto& stmt : stmts )
                        xs.push_back(escape(stmt->print()));
                    std::ranges::sort(xs);
                    ys.push_back(util::fmt("%s: %s", decl->id(), util::join(xs, ", ")));
                }

                std::ranges::sort(ys);
                return util::join(ys, ", ");
            };

            auto kill = [&]() -> std::string {
                if ( transfer.kill.empty() )
                    return "";
                return util::fmt("kill: [%s]", to_str(transfer.kill));
            }();

            auto in_out = [&]() -> std::string {
                return util::fmt("in: [%s] out: [%s]", to_str(transfer.in), to_str(transfer.out));
            }();

            auto aliases = [&]() {
                auto xs = util::toVector(transfer.maybe_alias |
                                         std::views::transform([&](auto* decl) { return escape(decl->id()); }));
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("aliases: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto keep = [&]() -> std::string { return transfer.keep ? "keep" : ""; }();

            xlabel = util::fmt("xlabel=\"%s\"", util::join(
                                                    std::vector{
                                                        std::move(read),
                                                        std::move(write),
                                                        std::move(gen),
                                                        std::move(kill),
                                                        std::move(in_out),
                                                        std::move(aliases),
                                                        std::move(keep),
                                                    } | std::views::filter([](const auto& x) { return ! x.empty(); }),
                                                    " "));
        }

        if ( const auto* meta = n->tryAs<MetaNode>() ) {
            if ( meta->isA<Start>() )
                ss << util::fmt("    %s [label=start shape=Mdiamond %s];\n", id, xlabel ? *xlabel : "");

            else if ( meta->isA<Flow>() )
                ss << util::fmt("    %s [shape=point %s];\n", id, xlabel ? *xlabel : "");

            else if ( const auto* scope = meta->tryAs<End>() )
                ss << util::fmt("    %s [label=\"end %s\" shape=triangle %s];\n", id, scope->scope->meta().location(),
                                xlabel ? *xlabel : "");

            else
                util::cannotBeReached();
        }

        else {
            ss << util::fmt("    %s [label=\"%s\" %s];\n", id, escape(n->print()), xlabel ? *xlabel : "");
        }
    }

    // Convert edge set into an ordinary map for deterministic sorting.
    for ( const auto& [id, e] : std::map(_graph.edges().begin(), _graph.edges().end()) ) {
        const auto& [from_, to_] = e;
        const auto* from = _graph.getNode(from_);
        const auto* to = _graph.getNode(to_);
        assert(from);
        assert(to);
        ss << util::fmt("    %s -> %s [label=\"%s\"];\n", node_ids.at((*from)->identity()),
                        node_ids.at((*to)->identity()), id);
    }

    ss << "}";

    return ss.str();
}

struct DataflowVisitor : visitor::PreOrder {
    DataflowVisitor(GraphNode root_) : root(root_) {}

    GraphNode root;
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
            auto* formal_arg = formal_args[i];
            auto* arg = args[i];

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
            }
        }

        // Since we do not know whether the called function is pure always keep it.
        // TODO(bbannier): remove calls to pure functions.
        transfer.keep = true;
    }

    void operator()(Expression* expression) override {
        // If the top-level CFG node is an expression we are looking at an expression for control flow -- keep it.
        if ( expression == root.value() )
            transfer.keep = true;
    }

    void operator()(expression::Name* name) override {
        auto* decl = name->resolvedDeclaration();
        if ( ! decl )
            return;

        // Ignore a few name kinds we are not interested in tracking.
        if ( decl->isA<declaration::Constant>() || decl->isA<declaration::Function>() ||
             decl->isA<declaration::Type>() )
            return;

        auto* node = root.value();
        // If the statement was a simple `Expression` unwrap it to get the more specific node.
        if ( auto* expr = node->tryAs<statement::Expression>() )
            node = expr->expression();

        // Check whether the name was used in an assignment.
        {
            // Figure out which side of the assignment this name is on.
            Node* node = name;
            do {
                if ( auto* assign_ = node->tryAs<expression::Assign>() ) {
                    if ( contains(*assign_->target(), *name) ) {
                        transfer.write.insert(decl);

                        // A LHS use generates a new value.
                        transfer.gen[decl] = root;

                        // If the assignment is to a member, mark the whole
                        // struct as read to encode that we still depend on the
                        // previous state of all the other member fields.
                        if ( assign_->target()->isA<operator_::struct_::MemberNonConst>() )
                            transfer.read.insert(decl);

                        // If we assign to a field (which should be `static`)
                        // we have a non-local side effect.
                        if ( decl->isA<declaration::Field>() )
                            transfer.keep = true;
                    }

                    if ( contains(*assign_->source(), *name) )
                        transfer.read.insert(decl);
                }
                node = node->parent();
            } while ( node && node != root.value() );
        }

        if ( node->isA<expression::Assign>() ) {
            // Nothing, handled above.
        }

        else if ( node->isA<statement::Declaration>() )
            // Names in declaration statements appear on the RHS.
            transfer.read.insert(decl);

        else if ( auto* d = node->tryAs<Declaration>() ) {
            // Names in declaration statements appear on the RHS.
            transfer.read.insert(decl);

            // If we declare a local variable record possible aliasing.
            UnqualifiedType* type = nullptr;

            if ( auto* local = d->tryAs<declaration::LocalVariable>() )
                type = local->type()->type();
            else if ( auto* global = d->tryAs<declaration::GlobalVariable>() )
                type = global->type()->type();

            if ( type && type->isAliasingType() )
                transfer.maybe_alias.insert(decl);
        }

        else if ( node->isA<statement::Return>() || node->isA<expression::LogicalOr>() ||
                  node->isA<expression::LogicalAnd>() || node->isA<expression::LogicalNot>() ||
                  node->isA<expression::Name>() )
            // Simply flows a value but does not generate or kill any.
            transfer.read.insert(decl);

        else {
            // All other nodes use the current decl, and are marked as unremovable.
            transfer.keep = true;
            transfer.read.insert(decl);
            transfer.write.insert(decl);
        }
    }

    void operator()(expression::ResolvedOperator* x) override {
        auto decl_for_name = [&](Node* n) -> Declaration* {
            assert(n);

            // If we do not directly have a name unwrap it.
            if ( auto* child = n->child(0) )
                n = child;

            if ( ! n )
                return nullptr;

            auto* name = n->tryAs<expression::Name>();
            if ( ! name )
                return nullptr;

            auto lookup = scope::lookupID<Declaration>(name->id(), root.value(), "declaration");
            if ( ! lookup )
                return nullptr;

            auto [decl, _] = lookup.value();
            return decl;
        };

        switch ( x->operator_().kind() ) {
            // If we access a member mark the whole value as used. We need to
            // do this so that a write to a single field does not invalidate
            // writes to other members.
            case operator_::Kind::Member: [[fallthrough]];
            case operator_::Kind::HasMember: [[fallthrough]];
            case operator_::Kind::TryMember: {
                auto* op1 = x->op1();
                if ( ! op1 )
                    break;

                auto* member = x->op1()->tryAs<expression::Member>();
                if ( ! member )
                    break;

                auto* op0 = decl_for_name(x->op0());
                if ( ! op0 )
                    break;

                transfer.read.insert(op0);
                return;
            }

            case operator_::Kind::Index: {
                auto* op0 = decl_for_name(x->op0());
                if ( ! op0 )
                    return;

                transfer.read.insert(op0);
                return;
            }
            case operator_::Kind::IndexAssign: {
                auto* op0 = decl_for_name(x->op0());
                if ( ! op0 )
                    return;

                transfer.read.insert(op0);
                transfer.write.insert(op0);
                return;
            }

            default:
                // Nothing.
                break;
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

        // Switch statements are reflected in the CFG as local variables and
        // different branches.
        //
        // TODO(bbannier): We currently model different switch cases as
        // separate branches, but removing a case would remove the whole switch
        // statement. Prevent that by explicitly requesting the variable
        // (which means also its switch statement) to be kept if we have any
        // cases.
        if ( auto* switch_ = x->parent()->tryAs<statement::Switch>(); switch_ && ! switch_->cases().empty() )
            transfer.keep = true;
    }
};

void CFG::_populateDataflow() {
    auto visit_node = [](const GraphNode& n) -> Transfer {
        if ( n->isA<MetaNode>() )
            return {};

        auto v = DataflowVisitor(n);
        visitor::visit(v, n.value());

        return std::move(v.transfer);
    };

    // Populate uses and the gen sets.
    for ( const auto& [id, n] : _graph.nodes() ) {
        if ( n.value() )
            _dataflow[n] = visit_node(n);
    }

    { // Encode aliasing information.

        // First make aliasing symmetric: to handle the case of e.g.,
        // references aliasing is stored symmetrically, i.e., if `a` aliases
        // `b`, `b` will also alias `a`.
        for ( const auto& [n, transfer] : _dataflow ) {
            for ( const auto& alias : transfer.maybe_alias ) {
                const auto* stmt = _graph.getNode(alias->identity());
                if ( ! stmt || ! stmt->value() || ! _dataflow.contains(*stmt) )
                    util::detail::internalError(
                        util::fmt("could not find CFG node for '%s' aliased in '%s'", alias->print(), n->print()));

                // Graph nodes either directly store a `Declaration` (for
                // globals), or `statement::Declaration` (for anything else).
                const auto* decl = n->tryAs<Declaration>();
                if ( ! decl ) {
                    if ( const auto* d = n->tryAs<const statement::Declaration>() )
                        decl = d->declaration();
                }
                if ( ! decl )
                    util::detail::internalError(util::fmt("could not get declaration from CFG node '%s'", n->print()));

                _dataflow.at(*stmt).maybe_alias.insert(const_cast<Declaration*>(decl));
            }
        }

        // Now copy the usage pattern to the aliased node.
        for ( auto& [n, transfer] : _dataflow ) {
            for ( const auto* r : transfer.read ) {
                const auto* stmt = _graph.getNode(r->identity());
                if ( ! stmt || ! stmt->value() || ! _dataflow.contains(*stmt) )
                    continue;

                for ( auto* alias : _dataflow.at(*stmt).maybe_alias )
                    transfer.read.insert(alias);
            }

            for ( const auto* w : transfer.write ) {
                const auto* stmt = _graph.getNode(w->identity());
                if ( ! stmt || ! stmt->value() || ! _dataflow.contains(*stmt) )
                    continue;

                for ( auto* alias : _dataflow.at(*stmt).maybe_alias )
                    transfer.write.insert(alias);
            }
        }
    }

    bool changed = false;
    do {
        changed = false;

        for ( auto& [n, transfer] : _dataflow ) {
            auto id = _graph.getNodeId(n);
            if ( ! id )
                util::detail::internalError(util::fmt(R"(could not determine ID of CFG node "%s")", n->print()));

            // Populate the in set.
            std::map<Declaration*, std::set<GraphNode>> new_in;
            for ( auto& pid : _graph.neighborsUpstream(*id) ) {
                const auto* p = _graph.getNode(pid);
                if ( ! p )
                    util::detail::internalError(util::fmt(R"(CFG node "%s" is unknown)", pid));

                for ( const auto& [n, stmts] : _dataflow.at(*p).out ) {
                    auto* decl = n->as<Declaration>();
                    // Make sure the entry exists.
                    auto& in = new_in[decl];

                    // Add the incoming statements.
                    for ( const auto& stmt : stmts ) {
                        in.insert(stmt);
                    }
                }
            }

            if ( transfer.in != new_in ) {
                transfer.in = std::move(new_in);
                changed = true;
            }

            // Populate the kill set.

            // If we generate an update to a decl, all previous decls get killed and do not
            // propagate.
            for ( auto& [decl, g] : transfer.gen ) {
                if ( auto it = transfer.in.find(decl); it != transfer.in.end() ) {
                    const auto& [_, prev] = *it;

                    changed |= ! transfer.kill.contains(decl);
                    auto& kill = transfer.kill[decl];

                    for ( const auto& p : prev ) {
                        auto [_, inserted] = kill.insert(p);
                        changed |= inserted;
                    }
                }
            }

            // If the current node ends a scope, do not propagate declarations local to it.
            if ( const auto* scope_end = n->tryAs<End>() ) {
                for ( auto& [decl, stmts] : transfer.in ) {
                    if ( contains(*scope_end->scope, *decl) ) {
                        changed |= ! transfer.kill.contains(decl);
                        auto& kill = transfer.kill[decl];

                        for ( const auto& stmt : stmts ) {
                            auto [_, inserted] = kill.insert(stmt);
                            changed |= inserted;
                        }
                    }
                }
            }

            // Populate the out set.
            std::map<Declaration*, std::set<GraphNode>> new_out;

            for ( const auto& [decl, g] : transfer.gen )
                new_out[decl].insert(g);

            for ( const auto& [decl, stmt] : transfer.in ) {
                // Add the incoming statements to the out set.
                for ( const auto& in : stmt ) {
                    if ( transfer.kill.contains(decl) && transfer.kill.at(decl).contains(in) )
                        continue;

                    // Make sure the entry exists.
                    auto& out = new_out[decl];

                    out.insert(in);
                }
            }

            if ( transfer.out != new_out ) {
                transfer.out = std::move(new_out);
                changed = true;
            }
        }
    } while ( changed );
}

// Helper function to output control flow graphs for statements.
static std::string dataflowDot(const hilti::Statement& stmt) {
    auto cfg = hilti::detail::cfg::CFG(&stmt);

    auto omit_dataflow = false;
    if ( const auto& env = rt::getenv("HILTI_OPTIMIZER_OMIT_CFG_DATAFLOW") )
        omit_dataflow = (*env == "1");

    return cfg.dot(omit_dataflow);
}

// Helper class to print CFGs to a debug stream.
class PrintCfgVisitor : public visitor::PreOrder {
    logging::DebugStream _stream;

public:
    PrintCfgVisitor(logging::DebugStream stream) : _stream(std::move(stream)) {}

    void operator()(declaration::Function* f) override {
        if ( auto* body = f->function()->body() )
            HILTI_DEBUG(_stream, util::fmt("Function '%s'\n%s", f->id(), dataflowDot(*body)));
    }

    void operator()(declaration::Module* m) override {
        if ( auto* body = m->statements() )
            HILTI_DEBUG(_stream, util::fmt("Module '%s'\n%s", m->id(), dataflowDot(*body)));
    }
};

void dump(logging::DebugStream stream, ASTRoot* root) {
    auto v = PrintCfgVisitor(std::move(stream));
    visitor::visit(v, root);
}

} // namespace hilti::detail::cfg
