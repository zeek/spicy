// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include "hilti/ast/types/tuple.h"

#include <algorithm>
#include <exception>

using namespace hilti;

std::vector<ID> type::Tuple::ids() const {
    auto ids = childsOfType<ID>();
    if ( ! ids.empty() )
        return ids;

    return std::vector<ID>(types().size(), ID());
}

std::optional<std::pair<int, Type>> type::Tuple::elementByID(const ID& id) {
    for ( const auto&& [i, e] : util::enumerate(elements()) ) {
        if ( e.first == id )
            return std::make_pair(i, e.second);
    }

    return {};
}
