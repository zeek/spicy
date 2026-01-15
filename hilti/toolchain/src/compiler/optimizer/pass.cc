// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/hilti/compiler/detail/optimizer/pass.h"

#include <cassert>

#include <hilti/ast/ast-context.h>
#include <hilti/ast/expressions/resolved-operator.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

Registry* optimizer::getPassRegistry() {
    static Registry registry;
    return &registry;
}

void optimizer::visitor::Collector::run(Node* node) {
    init();
    hilti::visitor::visit(*this, node ? node : context()->root());
    done();
}

bool optimizer::visitor::Mutator::run(Node* node) {
    init();
    hilti::visitor::visit(*this, node ? node : context()->root());
    done();

    return isModified();
}

void optimizer::visitor::Mutator::_trackASTChange(const Node* n) {
    // Determine the function or module changed by this replacement. We prefer
    // finding a function, and then don't record a change to the module. We
    // record a change to the module only for anything outside of a function.
    declaration::Module* module = nullptr;
    hilti::Function* function = nullptr;

    for ( auto* x = n->parent(); x; x = x->parent() ) {
        if ( auto* f = x->tryAs<Function>() ) {
            function = f;
            break;
        }

        if ( auto* m = x->tryAs<declaration::Module>() ) {
            module = m;
            break;
        }
    }

    assert(! (function && module));

    if ( function )
        state()->functionChanged(function);

    if ( module ) // we don't update anything when just deleting global nodes
        state()->moduleChanged(module);
}

void optimizer::visitor::Mutator::replaceNode(Node* old, Node* new_, const std::string& msg) {
    _trackASTChange(old);
    hilti::visitor::MutatingVisitorBase::replaceNode(old, new_, msg);
}

void optimizer::visitor::Mutator::removeNode(Node* old, const std::string& msg) {
    _trackASTChange(old);
    hilti::visitor::MutatingVisitorBase::removeNode(old, msg);
}

void optimizer::visitor::Mutator::recordChange(const Node* old, const std::string& msg) {
    _trackASTChange(old);
    hilti::visitor::MutatingVisitorBase::recordChange(old, msg);
}

optimizer::Registry::Registry() {
    if ( auto disabled = rt::getenv("HILTI_DISABLE_OPTIMIZER_PASSES"); disabled && ! disabled->empty() ) {
        auto range = util::split(*disabled, ":") | std::views::transform([](const auto& p) { return util::trim(p); });
        _disabled_passes = std::set(range.begin(), range.end());
    }
}

void optimizer::Registry::register_(PassInfo pinfo) {
    assert(! _pinfos.contains(pinfo));

    if ( ! _disabled_passes.contains(to_string(pinfo.id)) )
        _pinfos.emplace(pinfo);
    else
        HILTI_DEBUG(logging::debug::Optimizer, util::fmt("skipping disabled optimizer pass %s", to_string(pinfo.id)));
}
