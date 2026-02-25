// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>

#include <hilti/ast/forward.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/base/util.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>

namespace hilti::detail {

class Optimizer;

namespace optimizer {
namespace visitor {

/**
 * Visitor base class for collecting information from an AST during
 * optimization passes. Visitors derived from this class should not make any
 * modifications to the AST.
 */
class Collector : public hilti::visitor::PreOrder {
public:
    /**
     * Constructor.
     *
     * @param optimizer The optimizer instance running the pass.
     */
    Collector(Optimizer* optimizer) : _optimizer(optimizer) {}

    /** Destructor. */
    ~Collector() override = default;

    /** Returns the AST context being optimized. */
    auto* context() const { return _optimizer->context(); }

    /** Returns the current optimizer state for use by the pass. */
    auto* state() const { return _optimizer->state(); }

    /** Returns the optimizer instance passes into the constructor. */
    auto* optimizer() const { return _optimizer; }

    /**
     * Method that will execute before the visitor traverses the AST via
     * `run()`. The default implementation does nothing, but can be overridden
     * for custom initialization logic.
     */
    virtual void init() {};

    /**
     * Runs the visitor over the full AST. This executes `init()`, then visits
     * all nodes, and finally executes `done()`. It can be overridden for
     * custom behavior, but should generally keep following the same pattern.
     *
     * @param node The root node to start the traversal from; id null, starts from the AST root
     * @return true if the AST was modified, false otherwise.
     */
    virtual void run(Node* node = nullptr);

    /**
     * Method that will execute after the visitor traversed the AST via
     * `run()`. The default implementation does nothing, but can be overridden
     * for custom finalization logic.
     */
    virtual void done() {};

private:
    Optimizer* _optimizer = nullptr;
};

/**
 * Visitor base class for mutating an AST during optimization passes. Per the
 * contract between optimizer and passes, AST modifications must be performed
 * only via visitors derived from this class; and must only use the class's
 * provided API for doing/reporting so. This is so that the optimizer can keep
 * track of changes made to the AST by the pass. See `optimizer::PassInfo` for
 * more details.
 */
class Mutator : public hilti::visitor::MutatingPreOrder {
public:
    /**
     * Constructor.
     *
     * @param optimizer The optimizer instance running the pass.
     */
    Mutator(Optimizer* optimizer)
        : hilti::visitor::MutatingPreOrder(optimizer->builder(), hilti::logging::debug::Optimizer),
          _optimizer(optimizer) {}

    /** Destructor. */
    ~Mutator() override = default;

    /** Returns the AST context being optimized. */
    auto* context() const { return _optimizer->context(); }

    /** Returns the optimizer instance passes into the constructor. */
    auto* optimizer() const { return _optimizer; }

    /** Returns the current optimizer state for use by the pass. */
    auto* state() const { return _optimizer->state(); }

    /** Returns the AST builder to be used for any modifications by the pass. */
    auto* builder() const { return _optimizer->builder(); }

    /**
     * Replaces a node in the AST with a different one, tracking the change for the optimizer.
     *
     * @param old the node to be replaced
     * @param new_ the new node to insert in place of the old one
     * @param msg debug message describing the change
     */
    void replaceNode(Node* old, Node* new_, const std::string& msg = "") override;

    /**
     * Removes a node from the AST, tracking the change for the optimizer.
     *
     * @param old the node to be removed
     * @param msg debug message describing the change
     */
    void removeNode(Node* old, const std::string& msg) override;

    /**
     * Registers a change about to be made to a node. This should generally be
     * used only when making in-place changes to a node's attributes; prefer
     * using `replaceNode()` or `removeNode()` when possible.
     *
     * Note that this should be called *before* the actual change is made, so
     * that the old node state can be logged. Then the *msg* should describe
     * the change that will be made.
     *
     * @param old the node affected by the change, before(!) the change
     * @param msg debug message describing the change
     */
    void recordChange(const Node* old, const std::string& msg) override;

    /**
     * Method that will execute before the visitor traverses the AST via
     * `run()`. The default implementation does nothing, but can be overridden
     * for custom initialization logic.
     */
    virtual void init() {};

    /**
     * Runs the visitor over the full AST. This executes `init()`, then visits
     * all nodes, and finally executes `done()`. It can be overridden for
     * custom behavior, but should generally keep following the same pattern.
     *
     * @param node The root node to start the traversal from; it null, starts from the AST root
     * @return true if the AST was modified, false otherwise.
     */
    virtual bool run(Node* node = nullptr);

    /**
     * Method that will execute after the visitor traversed the AST via
     * `run()`. The default implementation does nothing, but can be overridden
     * for custom finalization logic.
     */
    virtual void done() {};

private:
    // Disabled. It's not needed and can be hard to use (because it needs both
    // old and new node state simultaneously).
    void recordChange(const Node* old, Node* changed, const std::string& msg = "") override { util::cannotBeReached(); }

    // Records a node as changed.
    void _trackASTChange(const Node* n);

    Optimizer* _optimizer = nullptr;
};

} // namespace visitor

// Class for global registry of available optimizer passes.
class Registry {
public:
    /** Constructor. */
    Registry();

    /**
     * Returns a set of all optimizer passes registered so far, sorted by their
     * order.
     */
    const auto& passes() const { return _pinfos; }

    /**
     * Registers a new optimizer pass. Usually, this is done via `RegisterPass`
     * instead of calling this directly.
     *
     * @param pinfo the pass info to register
     */
    void register_(PassInfo pinfo);

private:
    std::set<PassInfo> _pinfos;
    std::set<std::string> _disabled_passes;
};

/** Returns the global pass registry singleton. */
extern Registry* getPassRegistry();

/** Helper class to register an optimizer pass at static initialization time. */
class RegisterPass {
public:
    /**
     * Constructor registering the given pass info.
     *
     * @param pinfo the pass info to register
     */
    RegisterPass(PassInfo pinfo) { getPassRegistry()->register_(pinfo); }
};

} // namespace optimizer
} // namespace hilti::detail
