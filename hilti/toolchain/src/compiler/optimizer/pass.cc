// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#include "hilti/hilti/compiler/detail/optimizer/pass.h"

#include <hilti/ast/ast-context.h>
#include <hilti/ast/expressions/resolved-operator.h>

using namespace hilti;
using namespace hilti::detail;
using namespace hilti::detail::optimizer;

Registry* optimizer::getPassRegistry() {
    static Registry registry;
    return &registry;
}

void optimizer::visitor::Collector::run() {
    init();
    hilti::visitor::visit(*this, context()->root());
    done();
}

optimizer::Result optimizer::visitor::Mutator::run() {
    init();
    hilti::visitor::visit(*this, context()->root());
    done();

    return isModified() ? Result::Modified : Result::Unchanged;
}

void optimizer::visitor::Mutator::_trackASTChange(const Node* old) {
    // Determine the function or module changed by this replacement. We prefer
    // finding a function, and then don't record a change to the module. We
    // record a change to the module only for anything outside of a function.
    declaration::Module* module = nullptr;
    hilti::Function* function = nullptr;

    for ( auto* n = old->parent(); n; n = n->parent() ) {
        if ( auto* f = n->tryAs<Function>() ) {
            function = f;
            break;
        }

        if ( auto* m = n->tryAs<declaration::Module>() ) {
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

void optimizer::visitor::Mutator::recordChange(const Node* old, const std::string& msg) {
    _trackASTChange(old);
    hilti::visitor::MutatingVisitorBase::recordChange(old, msg);
}

void optimizer::visitor::Mutator::recordChange(const Node* old, Node* changed, const std::string& msg) {
    _trackASTChange(old);
    hilti::visitor::MutatingVisitorBase::recordChange(old, changed, msg);
}
