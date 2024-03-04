// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <optional>

#include <hilti/ast/type.h>
#include <hilti/base/timing.h>

#include <spicy/ast/visitor.h>
#include <spicy/compiler/detail/type-unifier.h>

using namespace spicy;

namespace {

// Computes the unified serialization of single unqualified type.
class VisitorSerializer : public visitor::PostOrder {
public:
    VisitorSerializer(hilti::type_unifier::Unifier* unifier) : unifier(unifier) {}

    hilti::type_unifier::Unifier* unifier;
};

} // namespace

bool type_unifier::detail::unifyType(hilti::type_unifier::Unifier* unifier, UnqualifiedType* t) {
    hilti::util::timing::Collector _("spicy/compiler/ast/type-unifier");

    auto old_size = unifier->serialization().size();
    VisitorSerializer(unifier).dispatch(t);
    return old_size != unifier->serialization().size();
}
