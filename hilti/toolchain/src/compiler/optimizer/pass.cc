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
