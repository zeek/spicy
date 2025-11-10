// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/forward.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/optimizer/cfg.h>

namespace hilti::logging::debug {
inline const hilti::logging::DebugStream Optimizer("optimizer");
inline const hilti::logging::DebugStream OptimizerDetail("optimizer-detail");
inline const hilti::logging::DebugStream OptimizerDump("optimizer-dump");
} // namespace hilti::logging::debug

namespace hilti::detail {

class Optimizer;

namespace optimizer {

struct PassInfo;

class ASTState {
public:
    ASTState(ASTContext* ctx, Builder* builder) : _context(ctx), _builder(builder) {}

    auto* context() { return _context; }
    auto* builder() { return _builder; }

    const auto& pass() const {
        assert(_pinfo);
        return *_pinfo;
    }

    void setPass(const PassInfo* pinfo) { _pinfo = pinfo; }

    void functionChanged(hilti::Function* function);
    void moduleChanged(declaration::Module* module);

    void updateState(const optimizer::PassInfo& pinfo);
    void checkState(const optimizer::PassInfo& pinfo);

    cfg::CFG* cfg(statement::Block* block);

private:
    void _normalizeModificationState();

    ASTContext* _context = nullptr;
    Builder* _builder = nullptr;
    const PassInfo* _pinfo = nullptr;

    std::unordered_map<Function*, declaration::Module*>
        _modified_functions; // mapping function to its containing module
    std::unordered_set<declaration::Module*> _modified_modules;

    std::unordered_map<statement::Block*, std::unique_ptr<cfg::CFG>> _cfgs;
};

enum class Requirements : uint16_t {
    Coercer = (1U << 1U),
    ConstantFolder = (1U << 2U),
    FullResolver = (1U << 3U),
    ScopeBuilder = (1U << 4U),
    TypeUnifier = (1U << 5U),
    CFG = (1U << 6U),

    None = 0U,
    All = ((1U << 16U) - 1U)
};

extern std::string to_string(bitmask<Requirements> r);

using Result = enum { Unchanged, Modified };

struct PassInfo {
    using Callback = Result (*)(Optimizer* opt);

    std::string name;
    size_t order;
    bool one_time = false;
    bool iterate = false;
    bitmask<Requirements> requires_afterwards = Requirements::All;
    Callback run;

    bool operator<(const PassInfo& other) const {
        return order != other.order ? order < other.order : name < other.name;
    }
};

} // namespace optimizer

class Optimizer {
public:
    Optimizer(ASTContext* ctx);

    /**
     * Applies optimizations to an AST. The AST must have been fully processed
     * before running optimization. This can be run multiple times if the same AST
     * needs to be re-optimized.
     */
    hilti::Result<Nothing> run();

    auto* builder() { return &_builder; }
    auto* context() { return _context; }
    optimizer::ASTState* state() { return &_state; }

    // TODO: Figure out where to put these.
    QualifiedType* innermostType(QualifiedType* type);
    std::optional<std::pair<ID, std::string>> idFeatureFromConstant(const ID& feature_constant);
    bool isFeatureFlag(const ID& id) { return util::startsWith(id.local(), "__feat%"); }

private:
    bool _runPass(const optimizer::PassInfo& pinfo, size_t round);
    void _dumpAST(ASTContext* ctx, std::string_view fname, std::string_view header);

    ASTContext* _context;
    Builder _builder;
    optimizer::ASTState _state;
};

} // namespace hilti::detail

enableEnumClassBitmask(hilti::detail::optimizer::Requirements); // must be in global scope
