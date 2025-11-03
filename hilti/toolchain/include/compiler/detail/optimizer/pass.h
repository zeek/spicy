// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/3rdparty/ArticleEnumClass-v2/EnumClass.h>

#include <hilti/ast/forward.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/logger.h>
#include <hilti/base/timing.h>
#include <hilti/compiler/detail/optimizer/optimizer.h>

namespace hilti::detail {

class Optimizer;

namespace optimizer {

namespace visitor {

class Collector : public hilti::visitor::PreOrder {
public:
    Collector(Optimizer* optimizer) : _optimizer(optimizer) {}
    ~Collector() override = default;

    auto* state() const { return _optimizer->state(); }
    auto* builder() const { return _optimizer->builder(); }
    auto* currentModule() const { return _current_module; }
    auto* context() const { return _optimizer->context(); }
    auto* optimizer() const { return _optimizer; }

    virtual void init() {};
    virtual void run();
    virtual void done() {};

    void operator()(declaration::Module* n) override { _current_module = n; }

private:
    Optimizer* _optimizer = nullptr;

    declaration::Module* _current_module = nullptr;
};

class Mutator : public hilti::visitor::MutatingPreOrder {
public:
    Mutator(Optimizer* optimizer)
        : hilti::visitor::MutatingPreOrder(optimizer->builder(), hilti::logging::debug::Optimizer),
          _optimizer(optimizer) {}
    ~Mutator() override = default;

    auto* state() const { return _optimizer->state(); }
    auto* builder() const { return _optimizer->builder(); }
    auto* currentModule() const { return _current_module; }
    auto* context() const { return _optimizer->context(); }
    auto* optimizer() const { return _optimizer; }

    void removeNode(Node* old, const std::string& msg = "") { replaceNode(old, nullptr, msg); }

    virtual void init() {};
    virtual Result run();
    virtual void done() {};

    void operator()(declaration::Module* n) override { _current_module = n; }

private:
    Optimizer* _optimizer = nullptr;

    declaration::Module* _current_module = nullptr;
};

} // namespace visitor

class Registry {
public:
    const auto& passes(Phase phase) const {
        if ( auto x = _pinfos.find(phase); x != _pinfos.end() )
            return x->second;
        else {
            static const std::vector<PassInfo> empty;
            return empty;
        }
    }

    void register_(PassInfo pinfo) { _pinfos[pinfo.phase].push_back(std::move(pinfo)); }

private:
    std::map<Phase, std::vector<PassInfo>> _pinfos;
};

extern Registry* getPassRegistry();

class RegisterPass {
public:
    RegisterPass(PassInfo pinfo) { getPassRegistry()->register_(std::move(pinfo)); }
};

} // namespace optimizer
} // namespace hilti::detail
