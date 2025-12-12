// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include <map>
#include <unordered_set>

#include <hilti/ast/declaration.h>
#include <hilti/ast/declarations/local-variable.h>
#include <hilti/ast/expressions/name.h>
#include <hilti/ast/statements/block.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>
#include <hilti/compiler/detail/optimizer/pass-id.h>
#include <hilti/compiler/detail/optimizer/pass.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

namespace {

// Collects declarations of local variables and references to them. This
// collector is intended to be run on a `Block`.
struct Collector : optimizer::visitor::Collector {
    Collector(Optimizer* optimizer) : optimizer::visitor::Collector(optimizer) {}

    void operator()(declaration::LocalVariable* local) override { variables[local]; }

    void operator()(expression::Name* name) override {
        // Since this is a pre-order visitor we will always visit declarations of locals before their use.
        if ( auto* decl = name->resolvedDeclaration()->tryAs<declaration::LocalVariable>();
             decl && variables.contains(decl) )
            variables[decl].insert(name);
    }

    struct VariablesSort {
        bool operator()(Node* a, Node* b) const { return a->identity() < b->identity(); }
    };

    // Enforce a consistent order of the declarations so their renaming below is deterministic.
    using Variables = std::map<declaration::LocalVariable*, std::unordered_set<expression::Name*>, VariablesSort>;
    Variables variables;
};

// Mutator which flattens blocks into their parent block. To do this it does the following:
//
// - detect blocks inside other blocks
// - rename all locals and their references in the block so it does not clash
//   with declarations from the parent scope
// - replace the block with its statements
// - at the end of the block, reset any variables aliasing locals from the
//   block to model RAII semantics
struct Mutator : optimizer::visitor::Mutator {
    Mutator(Optimizer* optimizer) : optimizer::visitor::Mutator(optimizer) {}

    // Tracks names which we will introduce into the parent scope. We don't
    // rely only on scope lookups since we only reresolve once all locals in a block
    // have been renamed.
    std::unordered_map<Function*, std::unordered_map<ID, Declaration*>> used_ids;

    void operator()(statement::Block* block) override {
        // Only work on blocks which are inside other blocks. This excludes
        // e.g., blocks which are function bodies, or bodies of `if` or
        // `while`.
        auto* parent = block->parent()->tryAs<statement::Block>();
        if ( ! parent )
            return;

        // We only work on blocks in functions, but not global blocks.
        auto* function = block->parent<Function>();
        if ( ! function )
            return;

        auto collector = Collector(optimizer());
        collector.run(block);

        // Rename IDs which would clash with existing ones from the parent scope.

        auto& used = used_ids[function];

        for ( auto& [decl, uses] : collector.variables ) {
            ID id = decl->id();
            while ( (used.contains(id) && used[id] != decl) || parent->getOrCreateScope()->has(id) )
                id = ID(id.str() + "_");

            used.emplace(id, decl);

            // No need to trigger ID change if there was no conflict.
            if ( id == decl->id() )
                continue;

            recordChange(decl, util::fmt(R"(renaming declaration "%s" -> "%s")", decl->id(), id));
            decl->setID(id);

            for ( auto* name : uses ) {
                recordChange(name, util::fmt(R"(renaming reference "%s" -> "%s")", name->id(), id));
                name->setID(id);
            }
        }

        // Fold contents of block into parent.
        auto statements = parent->statements();
        recordChange(parent, "inlining child block");
        parent->removeStatements();

        // Variables declared in the block would have previously gone
        // out of scope. Overwrite them to force any aliases to also
        // see an update.
        if ( ! statements.empty() ) {
            if ( auto* last = *statements.rbegin() ) {
                auto* cfg = state()->cfg(function->body());

                const auto& successors = cfg->graph().neighborsDownstream(last->identity());
                // A block should have at most one child, the statement following it.
                assert(successors.size() <= 1);
                if ( ! successors.empty() ) {
                    const auto* scope_end = cfg->graph().getNode(successors.front());
                    assert(scope_end);
                    assert((*scope_end)->isA<cfg::End>());
                    const auto& transfer = cfg->dataflow().at(*scope_end);
                    for ( auto&& [a, xx] : transfer.kill ) {
                        // Since loops and conditionals can have a block we check whether the block actually
                        // contains the declaration so we do not lifecycle variables declared in e.g., the loop
                        // control block.
                        if ( auto* local = a->tryAs<declaration::LocalVariable>();
                             local && cfg::contains(*block, *local) ) {
                            recordChange(local,
                                         "resetting block-local variable at the end of block since block will "
                                         "be removed");
                            block->addChild(context(), builder()->assign(builder()->id(local->id()),
                                                                         builder()->default_(local->type()->type())));
                        }
                    }
                }
            }
        }

        // Copy the original contents in order, but inline the block.
        for ( auto* c : statements ) {
            if ( c == block ) {
                recordChange(block, "inlining block");

                auto statements_ = block->statements();
                block->removeStatements();
                for ( auto* stmt : statements_ )
                    parent->add(context(), stmt);
            }

            else
                parent->add(context(), c);
        }
    }
};

optimizer::RegisterPass flatten_blocks(PassInfo{.id = PassID::FlattenBlocks,
                                                .guarantees = Guarantees::ConstantsFolded,
                                                .run = [](auto* optimizer) { return Mutator(optimizer).run(); }});

} // namespace
