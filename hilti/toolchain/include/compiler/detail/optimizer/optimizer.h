// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/ast/forward.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>

namespace hilti {

namespace logging::debug {
inline const hilti::logging::DebugStream Optimizer("optimizer");
inline const hilti::logging::DebugStream OptimizerCollect("optimizer-collect");
} // namespace logging::debug

namespace detail::optimizer {
/**
 * Applies optimizations to an AST. The AST must have been fully processed
 * before running optimization.
 */
bool optimize(Builder* builder, ASTRoot* root, bool first);

using OperatorUses = std::map<const Operator*, std::vector<expression::ResolvedOperator*>>;

class OptimizerVisitor;

using PassCreator = std::unique_ptr<OptimizerVisitor> (*)(Builder* builder, const OperatorUses* op_uses);
using Phase = size_t;


class PassRegistry {
public:
    const auto& creators() const { return _creators; }

    void register_(std::string name, std::pair<PassCreator, Phase> pass) {
        _creators.emplace(std::move(name), std::move(pass));
    }

private:
    std::map<std::string, std::pair<PassCreator, Phase>> _creators;
};

extern PassRegistry* getPassRegistry();

class RegisterPass {
public:
    RegisterPass(std::string name, std::pair<PassCreator, Phase> pass) {
        getPassRegistry()->register_(std::move(name), std::move(pass));
    }
};

extern QualifiedType* innermostType(QualifiedType* type);
extern std::optional<std::pair<ID, std::string>> idFeatureFromConstant(const ID& feature_constant);
inline bool isFeatureFlag(const ID& id) { return util::startsWith(id.local(), "__feat%"); }

class OptimizerVisitor : public visitor::MutatingPreOrder {
public:
    using visitor::MutatingPreOrder::MutatingPreOrder;

    enum class Stage { Collect, PruneUses, PruneDecls };
    Stage stage = Stage::Collect;
    declaration::Module* current_module = nullptr;

    void removeNode(Node* old, const std::string& msg = "") override { replaceNode(old, nullptr, msg); }

    OptimizerVisitor(Builder* builder, const logging::DebugStream& dbg, const OperatorUses* op_uses)
        : visitor::MutatingPreOrder(builder, dbg), _op_uses(op_uses) {}

    ~OptimizerVisitor() override = default;
    virtual void collect(Node*) {}
    virtual bool pruneUses(Node*) { return false; }
    virtual bool pruneDecls(Node*) { return false; }
    virtual void transform(Node* node) {}

    void operator()(declaration::Module* n) override { current_module = n; }

    const OperatorUses::mapped_type* uses(const Operator* x) const {
        if ( ! _op_uses->contains(x) )
            return nullptr;

        return &_op_uses->at(x);
    }

private:
    const OperatorUses* _op_uses = nullptr;
};


} // namespace detail::optimizer
} // namespace hilti
