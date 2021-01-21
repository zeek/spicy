// Copyright (c) 2020-2021 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/ctors/enum.h>
#include <hilti/ast/types/enum.h>

using namespace hilti;

std::vector<type::enum_::Label> type::Enum::_normalizeLabels(std::vector<type::enum_::Label> labels) {
    auto max = std::max_element(labels.begin(), labels.end(), [](auto l1, auto l2) { return l1.value() < l2.value(); });
    auto next_value = (max != labels.end() ? max->value() + 1 : 0);

    std::vector<type::enum_::Label> nlabels;

    for ( auto l : labels ) {
        if ( util::tolower(l.id()) == "undef" )
            throw std::out_of_range("reserved enum label 'Undef' cannot be redefined");

        if ( l.value() < 0 )
            nlabels.emplace_back(l.id(), next_value++, l.meta());
        else
            nlabels.push_back(std::move(l));
    }

    nlabels.emplace_back(ID("Undef"), -1);

    return nlabels;
}
