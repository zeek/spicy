// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>

#include <hilti/ast/types/tuple.h>

using namespace hilti;

type::tuple::Element::~Element() = default;

std::optional<std::pair<int, type::tuple::Element*>> type::Tuple::elementByID(const ID& id) const {
    int i = 0;
    for ( const auto& e : elements() ) {
        if ( e->id() == id )
            return std::make_optional(std::make_pair(i, e));

        i++;
    }

    return {};
}

bool type::Tuple::isResolved(node::CycleDetector* cd) const {
    const auto& cs = children();

    return std::all_of(cs.begin(), cs.end(), [&](const auto& c) {
        auto t = c->template tryAs<QualifiedType>();
        return ! t || t->isResolved(cd);
    });
}
