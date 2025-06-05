// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include "hilti/compiler/detail/cfg.h"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <map>
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

namespace hilti::detail::cfg {

uint64_t MetaNode::instances = 0;

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

CFG::CFG(const Node* root)
    : _begin(getOrAddNode(create_meta_node<Start>())), _end(getOrAddNode(create_meta_node<End>())) {
    assert(root && root->isA<statement::Block>() && "only building from blocks currently supported");

    _begin = addGlobals(_begin, *root);
    auto* last = addBlock(_begin, root->children(), root);
    if ( last != _end )
        addEdge(last, _end);
}

Node* CFG::addGlobals(Node* parent, const Node& root) {
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

        auto* stmt = getOrAddNode(global);
        addEdge(parent, stmt);
        parent = stmt;
    }

    return parent;
}

Node* CFG::addBlock(Node* parent, const Nodes& stmts, const Node* scope) {
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
    auto* scope_end = getOrAddNode(create_meta_node<ScopeEnd>(scope));

    // Add all statements which are part of the normal flow.
    for ( auto&& c : (last != stmts.end() ? Nodes(stmts.begin(), last) : stmts) ) {
        if ( ! c )
            continue;

        if ( auto&& while_ = c->tryAs<statement::While>() )
            parent = addWhile(parent, *while_, scope_end);

        else if ( auto&& for_ = c->tryAs<statement::For>() )
            parent = addFor(parent, *for_);

        else if ( auto&& if_ = c->tryAs<statement::If>() )
            parent = addIf(parent, *if_);

        else if ( auto&& try_catch = c->tryAs<statement::Try>() )
            parent = addTryCatch(parent, *try_catch);

        else if ( auto&& throw_ = c->tryAs<statement::Throw>() )
            parent = addThrow(parent, *throw_, scope_end);

        else if ( auto&& return_ = c->tryAs<statement::Return>() )
            parent = addReturn(parent, return_->expression());

        else if ( c->isA<statement::Continue>() || c->isA<statement::Break>() )
            // `continue`/`break` statements only add flow, but no data.
            ; // Nothing.

        else if ( auto&& call = c->tryAs<operator_::function::Call>() )
            parent = addCall(parent, call);

        else if ( auto&& block = c->tryAs<statement::Block>() )
            parent = addBlock(parent, block->statements(), block);

        else {
            if ( ! c || ! c->isA<Statement>() )
                continue;

            auto* cc = getOrAddNode(c);

            addEdge(parent, cc);

            auto* x = addBlock(parent, c->children(), c);

            // We might have added a dead edge to a `ScopeEnd` with
            // `add_block`, clean it up again.
            if ( x && x->isA<ScopeEnd>() )
                g.removeNode(x->identity());

            parent = cc;
        }
    }

    // Add unreachable flows.
    if ( has_dead_flow && last != stmts.end() ) {
        auto* next = addBlock(nullptr, Nodes{last, stmts.end()}, scope);
        auto* mix = getOrAddNode(create_meta_node<Flow>());
        addEdge(parent, mix);
        addEdge(next, mix);
        parent = mix;
    }

    // Connect the scope end to prevent leaking of locals out of their blocks.
    addEdge(parent, scope_end);
    parent = scope_end;

    return parent;
}

Node* CFG::addFor(Node* parent, const statement::For& for_) {
    auto&& sequence = getOrAddNode(for_.sequence());
    addEdge(parent, sequence);

    auto&& local = getOrAddNode(for_.local());
    addEdge(sequence, local);

    auto* body_end = addBlock(local, for_.body()->children(), for_.body());
    addEdge(body_end, sequence);

    auto* scope_end = getOrAddNode(create_meta_node<ScopeEnd>(&for_));
    addEdge(sequence, scope_end);

    return scope_end;
}

Node* CFG::addWhile(Node* parent, const statement::While& while_, Node* scope_end) {
    if ( auto* init = while_.init() ) {
        auto* init_ = getOrAddNode(init);
        addEdge(parent, init_);
        addEdge(init_, scope_end);

        parent = init_;
    }

    if ( auto* c = while_.condition() ) {
        auto&& condition = getOrAddNode(c);
        addEdge(parent, condition);
        parent = condition;
    }

    auto* body_end = addBlock(parent, while_.body()->children(), while_.body());
    addEdge(body_end, parent);

    auto* mix = getOrAddNode(create_meta_node<Flow>());
    addEdge(parent, mix);

    if ( auto&& else_ = while_.else_() ) {
        auto&& else_end = addBlock(parent, else_->children(), else_);
        addEdge(else_end, mix);
    }

    return mix;
}

Node* CFG::addIf(Node* parent, const statement::If& if_) {
    if ( auto* init = if_.init() ) {
        auto* init_ = getOrAddNode(init);
        addEdge(parent, init_);
        parent = init_;
    }

    auto&& condition = getOrAddNode(if_.condition());
    addEdge(parent, condition);

    auto* mix = getOrAddNode(create_meta_node<Flow>());
    auto* true_end = addBlock(condition, if_.true_()->children(), if_.true_());

    addEdge(true_end, mix);

    if ( auto* false_ = if_.false_() ) {
        auto* false_end = addBlock(condition, false_->children(), false_);
        addEdge(false_end, mix);
    }

    else
        addEdge(condition, mix);

    return mix;
}

Node* CFG::addTryCatch(Node* parent, const statement::Try& try_catch) {
    auto* try_ = addBlock(parent, try_catch.body()->children(), try_catch.body());

    // Connect into node combining flows from `try` and `catch` blocks.
    auto* mix_after = getOrAddNode(create_meta_node<Flow>());
    addEdge(try_, mix_after);

    // Since the `try` block can throw connect into node flowing into all `catch` blocks.
    auto* mix_into_catches = getOrAddNode(create_meta_node<Flow>());
    addEdge(try_, mix_into_catches);

    for ( auto&& catch_ : try_catch.catches() ) {
        auto* catch_end = addBlock(mix_into_catches, catch_->body()->children(), catch_);

        addEdge(catch_end, mix_after);
    }

    return mix_after;
}

Node* CFG::addReturn(Node* parent, const Node* expression) {
    if ( expression ) {
        // We store the return statement to make us of it in data flow analysis.
        auto* r = getOrAddNode(expression->parent());
        addEdge(parent, r);
        addEdge(r, _end);
        return _end;
    }

    return parent;
}

Node* CFG::addThrow(Node* parent, statement::Throw& throw_, Node* scope_end) {
    if ( auto* expression = throw_.expression() ) {
        auto* expr = getOrAddNode(expression);

        addEdge(parent, expr);
        addEdge(expr, scope_end);
    }
    else
        addEdge(parent, scope_end);

    return scope_end;
}

Node* CFG::addCall(Node* parent, operator_::function::Call* call) {
    auto* c = getOrAddNode(call);
    addEdge(parent, c);
    return c;
}

Node* CFG::getOrAddNode(Node* n) {
    if ( const auto* x = g.getNode(n->identity()) )
        return *x;

    g.addNode(n, n->identity());
    return n;
}

void CFG::addEdge(Node* from, Node* to) {
    if ( ! from || ! to )
        return;

    // The end node does not have outgoing edges.
    if ( from == _end )
        return;

    if ( const auto& xs = g.neighborsDownstream(from->identity());
         xs.end() != std::find_if(xs.begin(), xs.end(), [&](const auto& t) { return t == to->identity(); }) )
        return;
    else {
        g.addEdge(from->identity(), to->identity());
        return;
    }
}

std::string CFG::dot() const {
    std::stringstream ss;

    ss << "digraph {\n";

    std::unordered_map<uintptr_t, size_t> node_ids; // Deterministic node ids.

    std::vector<Node*> sorted_nodes;
    std::transform(g.nodes().begin(), g.nodes().end(), std::back_inserter(sorted_nodes),
                   [](const auto& p) { return p.second; });
    std::sort(sorted_nodes.begin(), sorted_nodes.end(),
              [](const Node* a, const Node* b) { return a && b && a->identity() < b->identity(); });

    auto escape = [](std::string_view s) { return rt::escapeUTF8(s, rt::render_style::UTF8::EscapeQuotes); };

    for ( auto&& n : sorted_nodes ) {
        auto id = node_ids.size();
        node_ids.insert({n->identity(), id});

        std::optional<std::string> xlabel;
        if ( auto it = _dataflow.find(n); it != _dataflow.end() ) {
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
                                     escape(node->print()));
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
                                                            return escape(x->print());
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
                    auto ys = util::transformToVector(xs, [&](auto&& x) { return escape(x->print()); });
                    std::sort(ys.begin(), ys.end());
                    return util::join(ys, ", ");
                };

                return util::fmt("reach: { in: [%s] out: [%s] }", to_str(r->in), to_str(r->out));
            }();

            auto aliases = [&]() {
                auto xs = util::transformToVector(transfer.maybe_alias, [&](auto* decl) {
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

        if ( auto&& meta = n->tryAs<MetaNode>() ) {
            if ( meta->isA<Start>() )
                ss << util::fmt("    %s [label=start shape=Mdiamond %s];\n", id, xlabel ? *xlabel : "");

            else if ( meta->isA<End>() )
                ss << util::fmt("    %s [label=end shape=Msquare %s];\n", id, xlabel ? *xlabel : "");

            else if ( meta->isA<Flow>() )
                ss << util::fmt("    %s [shape=point %s];\n", id, xlabel ? *xlabel : "");

            else if ( auto* scope = meta->tryAs<ScopeEnd>() ) {
                ss << util::fmt("    %s [label=\"scope_end %s\" shape=triangle %s];\n", id,
                                scope->scope->meta().location(), xlabel ? *xlabel : "");
            }

            else
                util::cannotBeReached();
        }

        else {
            ss << util::fmt("    %s [label=\"%s\" %s];\n", id, escape(n->print()), xlabel ? *xlabel : "");
        }
    }

    // Convert edge set into an ordinary map for deterministic sorting.
    for ( auto&& [id, e] : std::map(g.edges().begin(), g.edges().end()) ) {
        auto&& [from_, to_] = e;
        auto&& from = g.getNode(from_);
        auto&& to = g.getNode(to_);
        assert(from);
        assert(to);
        ss << util::fmt("    %s -> %s [label=\"%s\"];\n", node_ids.at((*from)->identity()),
                        node_ids.at((*to)->identity()), id);
    }

    ss << "}";

    return ss.str();
}

std::unordered_set<Node*> CFG::unreachableNodes() const {
    std::unordered_set<Node*> result;
    for ( auto&& [id, n] : g.nodes() ) {
        if ( n && ! n->isA<MetaNode>() && g.neighborsUpstream(id).empty() )
            result.insert(n);
    }

    return result;
}

struct DataflowVisitor : visitor::PreOrder {
    DataflowVisitor(Node* root_) : root(root_) {}

    Node* root = nullptr;
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
        if ( expression == root )
            transfer.keep = true;
    }

    void operator()(expression::Name* name) override {
        auto* decl = name->resolvedDeclaration();
        if ( ! decl )
            return;

        auto* stmt = root;
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
            } while ( x && x != root );
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
                    transfer.maybe_alias.insert(decl);
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

void CFG::populateDataflow() {
    auto visit_node = [](Node* n) -> Transfer {
        if ( n->isA<MetaNode>() )
            return {};

        auto v = DataflowVisitor(n);
        visitor::visit(v, n);

        return std::move(v.transfer);
    };

    // Populate uses and the gen sets.
    for ( auto&& [id, n] : g.nodes() ) {
        if ( n )
            _dataflow[n] = visit_node(n);
    }

    { // Encode aliasing information.
        auto find_node = [&](const hilti::Node* const n) -> Node* {
            const auto* x = g.getNode(n->identity());
            if ( x )
                return *x;

            return nullptr;
        };

        // First make aliasing symmetric: to handle the case of e.g.,
        // references aliasing is stored symmetrically, i.e., if `a` aliases
        // `b`, `b` will also alias `a`.
        for ( auto&& [n, transfer] : _dataflow ) {
            for ( const auto* alias : transfer.maybe_alias ) {
                auto* stmt = find_node(alias);
                if ( ! stmt || ! _dataflow.count(stmt) )
                    // Could not find node declaring aliased name.
                    util::detail::internalError(
                        util::fmt(R"(could not find CFG node for "%s" aliased in "%s")", alias->print(), n->print()));


                _dataflow.at(stmt).maybe_alias.insert(n);
            }
        }

        // Now mark aliased nodes as used.
        for ( auto&& [n, transfer] : _dataflow ) {
            for ( const auto* use : transfer.use ) {
                auto* stmt = find_node(use);
                if ( ! stmt || ! _dataflow.count(stmt) )
                    continue;

                for ( auto* alias : _dataflow.at(stmt).maybe_alias )
                    transfer.use.insert(alias);
            }
        }
    }

    { // Populate the kill sets.
        std::map<const Node*, std::unordered_set<Node*>> gens;
        for ( auto&& [_, transfer] : _dataflow ) {
            for ( auto&& [d, n] : transfer.gen )
                gens[d].insert(n);
        }

        for ( auto&& [id, n] : g.nodes() ) {
            auto& transfer = _dataflow[n];

            for ( auto&& [d, ns] : gens ) {
                auto* d_ = const_cast<Node*>(d);
                auto x = transfer.gen.find(d_);
                // Only kill gens also generated in this node.
                if ( x == transfer.gen.end() )
                    continue;

                for ( auto* nn : ns ) {
                    // Do not kill the gen in this node.
                    if ( x->second != nn )
                        transfer.kill[d_].insert(nn);
                }
            }
        }
    }
}

void CFG::populateReachableExpressions() {
    if ( _dataflow.empty() )
        populateDataflow();

    const auto& nodes = g.nodes();

    // Reset reachability information.
    for ( auto&& [id, n] : nodes )
        _dataflow.at(n).reachability = Reachability();

    // Compute in and out sets for each node.
    while ( true ) {
        bool changed = false;

        for ( const auto& [id, n] : nodes ) {
            if ( ! n )
                continue;

            auto& reachability = _dataflow[n].reachability;
            auto& in = reachability->in;
            auto& out = reachability->out;

            auto* scope_end = n->tryAs<ScopeEnd>();

            // The in set is the union of all incoming nodes.
            for ( const auto& n : g.neighborsUpstream(n->identity()) ) {
                const auto* f = g.getNode(n);
                assert(f);
                const auto& from = *f;

                auto& from_ = _dataflow.at(from).reachability->out; // Must already exist.

                for ( auto&& f : from_ ) {
                    // Prevent leaking of locals out of their scope.
                    //
                    // At the end of scopes (currently: blocks) we insert a `ScopeEnd` node. Most locals must not
                    // flow out of this node, we however allow locals flowing from `return` statements to precede.
                    if ( scope_end ) {
                        assert(_dataflow.count(f));
                        const auto& transfer = _dataflow[f];

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
            const auto& gen = _dataflow.at(n).gen;
            const auto& kill = _dataflow.at(n).kill;

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

std::vector<Node*> CFG::unreachableStatements() const {
    // This can only be called after reachability information has been populated.
    assert(! _dataflow.empty());
    assert(_dataflow.begin()->second.reachability);

    std::map<Node*, uint64_t> uses;

    // Loop over all nodes.
    for ( const auto& [n, transfer] : _dataflow ) {
        // Check whether we want to declare any of the statements used. We currently do this for
        // - `inout` parameters since their result is can be seen after the function has ended,
        // - globals since they could be used elsewhere without us being able to see it,
        // - `self` expression since they live on beyond the current block.
        if ( n->isA<End>() ) {
            assert(_dataflow.count(n));
            // If we saw an operation an `inout` parameter at the end of the flow, mark the parameter as used.
            // For each incoming statement ...
            for ( auto&& in : transfer.reachability->in ) {
                assert(_dataflow.count(in));
                // If the statement generated an update to the value ...
                for ( auto&& [n_, _] : _dataflow.at(in).gen ) {
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

        if ( ! n->isA<MetaNode>() )
            (void)uses[n]; // Record statement if not already known.

        // For each update to a declaration generated by a node ...
        for ( auto&& [decl, node] : transfer.gen ) {
            // Search for nodes making use of the statement.
            for ( auto&& [n_, t] : _dataflow ) {
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

    std::vector<Node*> result;
    for ( auto&& [n, uses] : uses ) {
        if ( uses > 0 )
            continue;

        if ( _dataflow.at(n).keep )
            continue;

        result.push_back(n);
    }

    return result;
}

} // namespace hilti::detail::cfg
