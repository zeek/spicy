// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/builder/all.h>
#include <hilti/ast/ctors/coerced.h>
#include <hilti/ast/ctors/tuple.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/global.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/operators/all.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;
using namespace hilti;

namespace {

struct Visitor : public visitor::PostOrder<void, Visitor> {
    Visitor(hilti::Module* module) : module(module) {}

    hilti::Module* module;
    bool modified = false;

    Expression argument(const Expression& args, int i) {
        auto ctor = args.as<expression::Ctor>().ctor();

        if ( auto x = ctor.tryAs<ctor::Coerced>() )
            ctor = x->coercedCtor();

        return ctor.as<ctor::Tuple>().value()[i];
    }

    template<typename T>
    void replaceNode(position_t& p, T&& n) {
        auto x = p.node;
        p.node = std::move(n);
        p.node.setOriginalNode(module->preserve(x));
        modified = true;
    }
};

} // anonymous namespace

bool spicy::detail::resolveOperators(hilti::Node* root, hilti::Unit* unit) {
    util::timing::Collector _("spicy/compiler/resolve-operators");

    auto v = Visitor(&root->as<hilti::Module>());
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified;
}
