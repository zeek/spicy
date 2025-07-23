// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

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

#include <hilti/ast/attribute.h>
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
#include <hilti/ast/expressions/member.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/expressions/resolved-operator.h>
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

// Helper function to check whether some `inner` node is a child of an `outer` node.
static bool _contains(const Node& outer, const Node& inner) {
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
    auto last = _addBlock(_begin, root->children(), root);
    if ( last != _end )
        _addEdge(last, _end);

    // Clean up artifacts from CFG construction.
    //
    // - `End` nodes with no incoming edges. These can arise if blocks never
    //   flow through their end node, e.g., due to early return.
    while ( true ) {
        std::set<uintptr_t> dead_ends;

        for ( const auto& [id, n] : g.nodes() ) {
            if ( n->isA<End>() && g.neighborsUpstream(id).empty() )
                dead_ends.insert(id);
        }

        for ( const auto& id : dead_ends )
            g.removeNode(id);

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
            auto cc = _getOrAddNode(stmt);

            _addEdge(predecessor, cc);

            auto x = _addBlock(predecessor, stmt->children(), stmt);

            // We might have added a dead edge to a `ScopeEnd` with
            // `add_block`, clean it up again.
            if ( x.value() && x->isA<End>() )
                g.removeNode(x->identity());

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
    if ( const auto* x = g.getNode(n->identity()) )
        return *x;

    g.addNode(n, n->identity());
    return n;
}

void CFG::_addEdge(const GraphNode& from, const GraphNode& to) {
    if ( ! from.value() || ! to.value() )
        return;

    // The end node does not have outgoing edges.
    if ( from == _end )
        return;

    if ( const auto& xs = g.neighborsDownstream(from->identity());
         xs.end() != std::ranges::find_if(xs, [&](const auto& t) { return t == to->identity(); }) )
        return;
    else {
        g.addEdge(from->identity(), to->identity());
        return;
    }
}

void detail::cfg::CFG::removeNode(Node* node) {
    auto id = node->identity();

    const auto& out = g.neighborsDownstream(id);
    const auto& in = g.neighborsUpstream(id);

    // Create new edges between incoming and outgoing nodes.
    for ( const auto& i : in ) {
        for ( const auto& o : out )
            g.addEdge(i, o);
    }

    g.removeNode(id);
}

std::string CFG::dot() const {
    std::stringstream ss;

    ss << "digraph {\n";

    std::unordered_map<uintptr_t, size_t> node_ids; // Deterministic node ids.

    std::vector<GraphNode> sorted_nodes;
    std::transform(g.nodes().begin(), g.nodes().end(), std::back_inserter(sorted_nodes),
                   [](const auto& p) { return p.second; });
    std::ranges::sort(sorted_nodes, [](const GraphNode& a, const GraphNode& b) {
        return a.value() && b.value() && a->identity() < b->identity();
    });

    auto escape = [](std::string_view s) { return rt::escapeUTF8(s, rt::render_style::UTF8::EscapeQuotes); };

    for ( const auto& n : sorted_nodes ) {
        auto id = node_ids.size();
        node_ids.insert({n->identity(), id});

        std::optional<std::string> xlabel;
        if ( auto it = _dataflow.find(n); it != _dataflow.end() ) {
            const auto& transfer = it->second;

            auto read = [&]() {
                auto xs = util::transformToVector(transfer.read, [&](auto* decl) { return escape(decl->id()); });
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("read: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto write = [&]() {
                auto xs = util::transformToVector(transfer.write, [&](auto* decl) { return escape(decl->id()); });
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("write: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto gen = [&]() {
                auto xs = util::transformToVector(transfer.gen, [&](const auto& kv) {
                    const auto& [decl, node] = kv;
                    return util::fmt("%s: %s", escape(decl->id()), escape(node->print()));
                });
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("gen: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto kill = [&]() {
                auto xs = util::transformToVector(transfer.kill, [&](const auto& stmt) {
                    return util::fmt("%s", escape(stmt->print()));
                });
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("kill: [%s]", util::join(xs, " "));
                else
                    return std::string();
            }();

            auto in_out = [&]() -> std::string {
                auto to_str = [&](const auto& xs) {
                    std::vector<std::string> ys;
                    for ( const auto& [_, stmts] : xs ) {
                        for ( const auto& stmt : stmts )
                            ys.push_back(escape(stmt->print()));
                    }

                    std::ranges::sort(ys);
                    return util::join(ys, ", ");
                };

                return util::fmt("in: [%s] out: [%s]", to_str(transfer.in), to_str(transfer.out));
            }();

            auto aliases = [&]() {
                auto xs = util::transformToVector(transfer.maybe_alias, [&](auto* decl) { return escape(decl->id()); });
                std::ranges::sort(xs);
                if ( ! xs.empty() )
                    return util::fmt("aliases: [%s]", util::join(xs, ", "));
                else
                    return std::string();
            }();

            auto keep = [&]() -> std::string { return transfer.keep ? "keep" : ""; }();

            xlabel = util::fmt("xlabel=\"%s\"",
                               util::join(util::filter(std::vector{read, write, gen, kill, in_out, aliases, keep},
                                                       [](const auto& x) { return ! x.empty(); }),
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
    for ( const auto& [id, e] : std::map(g.edges().begin(), g.edges().end()) ) {
        const auto& [from_, to_] = e;
        const auto* from = g.getNode(from_);
        const auto* to = g.getNode(to_);
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
            };
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

        auto* stmt = root.value();
        // If the statement was a simple `Expression` unwrap it to get the more specific node.
        if ( auto* expr = stmt->tryAs<statement::Expression>() )
            stmt = expr->expression();

        if ( auto* assign = stmt->tryAs<expression::Assign>() ) {
            // Figure out which side of the assignment this name is on.
            std::set<Side> uses;
            Node* x = name;
            do {
                if ( x == assign->target() ) {
                    uses.insert(Side::LHS);
                    break;
                }

                if ( x == assign->source() ) {
                    uses.insert(Side::RHS);
                    break;
                }

                x = x->parent();
            } while ( x && x != root.value() );
            assert(! uses.empty());

            for ( auto side : uses )
                switch ( side ) {
                    case Side::RHS: transfer.read.insert(decl); break;
                    case Side::LHS: {
                        transfer.write.insert(decl);

                        // If the assignment is to a member, mark the whole
                        // struct as read to encode that we still depend on the
                        // previous state of all the other member fields.
                        if ( assign->target()->isA<operator_::struct_::MemberNonConst>() )
                            transfer.read.insert(decl);

                        break;
                    }
                }

            // A LHS use generates a new value.
            if ( uses.contains(Side::LHS) )
                transfer.gen[decl] = root;
        }

        else if ( stmt->isA<statement::Declaration>() )
            // Names in declaration statements appear on the RHS.
            transfer.read.insert(decl);

        else if ( auto* global = stmt->tryAs<declaration::GlobalVariable>() ) {
            // Names in the global declaration appear on the RHS.
            transfer.read.insert(decl);

            if ( auto* type = global->type()->type() ) {
                if ( type->isAliasingType() )
                    transfer.maybe_alias.insert(decl);
            }
        }

        else if ( stmt->isA<statement::Return>() )
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
    for ( const auto& [id, n] : g.nodes() ) {
        if ( n.value() )
            _dataflow[n] = visit_node(n);
    }

    { // Encode aliasing information.

        // First make aliasing symmetric: to handle the case of e.g.,
        // references aliasing is stored symmetrically, i.e., if `a` aliases
        // `b`, `b` will also alias `a`.
        for ( const auto& [n, transfer] : _dataflow ) {
            for ( const auto& alias : transfer.maybe_alias ) {
                const auto* stmt = g.getNode(alias->identity());
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
                const auto* stmt = g.getNode(r->identity());
                if ( ! stmt || ! stmt->value() || ! _dataflow.contains(*stmt) )
                    continue;

                for ( auto* alias : _dataflow.at(*stmt).maybe_alias )
                    transfer.read.insert(alias);
            }

            for ( const auto* w : transfer.write ) {
                const auto* stmt = g.getNode(w->identity());
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
            auto id = g.getNodeId(n);
            if ( ! id )
                util::detail::internalError(util::fmt(R"(could not determine ID of CFG node "%s")", n->print()));

            // Populate the in set.
            std::unordered_map<Declaration*, std::unordered_set<GraphNode>> new_in;
            for ( auto& pid : g.neighborsUpstream(*id) ) {
                const auto* p = g.getNode(pid);
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

                    for ( const auto& p : prev ) {
                        auto [_, inserted] = transfer.kill.insert(p);
                        changed |= inserted;
                    }
                }
            }

            // If the current node ends a scope, do not propagate declarations local to it.
            if ( const auto* scope_end = n->tryAs<End>() ) {
                for ( auto& [decl, stmts] : transfer.in ) {
                    if ( _contains(*scope_end->scope, *decl) ) {
                        for ( const auto& stmt : stmts ) {
                            auto [_, inserted] = transfer.kill.insert(stmt);
                            changed |= inserted;
                        }
                    }
                }
            }

            // Populate the out set.
            std::unordered_map<Declaration*, std::unordered_set<GraphNode>> new_out;

            for ( const auto& [decl, g] : transfer.gen )
                new_out[decl].insert(g);

            for ( const auto& [decl, stmt] : transfer.in ) {
                // Add the incoming statements to the out set.
                for ( const auto& in : stmt ) {
                    if ( transfer.kill.contains(in) )
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

} // namespace hilti::detail::cfg
