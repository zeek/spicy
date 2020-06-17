// Copyright (c) 2020 by the Zeek Project. See LICENSE for details.

#include <hilti/ast/expressions/ctor.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/unit.h>
#include <hilti/global.h>
#include <spicy/ast/detail/visitor.h>
#include <spicy/compiler/detail/visitors.h>

using namespace spicy;

namespace {

struct Visitor : public hilti::visitor::PreOrder<void, Visitor> {
    // Currently nothing to do here. Note that we coerce field attributes on
    // access through builder::coerceTo().

    bool modified = false;

    Expression coerceToPending(const Expression& e, const Type& t) {
        return hilti::expression::PendingCoerced(e, t, e.meta());
    }

    template<typename T>
    void replaceNode(position_t* p, T&& n) {
        p->node = std::forward<T>(n);
        modified = true;
    }
};

} // anonymous namespace

bool spicy::detail::applyCoercions(Node* root, hilti::Unit* /* unit */) {
    hilti::util::timing::Collector _("spicy/compiler/apply-coercions");

    auto v = Visitor();
    for ( auto i : v.walk(root) )
        v.dispatch(i);

    return v.modified;
}
