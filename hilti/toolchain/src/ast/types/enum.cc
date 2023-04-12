// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/ctors/enum.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/types/enum.h>

using namespace hilti;

std::vector<Declaration> type::Enum::_normalizeLabels(std::vector<type::enum_::Label> labels) {
    auto max = std::max_element(labels.begin(), labels.end(),
                                [](const auto& l1, const auto& l2) { return l1.value() < l2.value(); });
    auto next_value = (max != labels.end() ? max->value() + 1 : 0);

    std::vector<Declaration> nlabels;

    for ( auto&& l : labels ) {
        if ( util::tolower(l.id()) == "undef" )
            throw std::out_of_range("reserved enum label 'Undef' cannot be redefined");

        type::enum_::Label nlabel;

        if ( l.value() < 0 )
            nlabel = type::enum_::Label(l.id(), next_value++, l.meta());
        else
            nlabel = std::move(l);

        Declaration d = declaration::Constant(nlabel.id(), expression::Ctor(ctor::Enum(nlabel)));
        nlabels.push_back(std::move(d));
    }

    auto undef_label = type::enum_::Label(ID("Undef"), -1);
    auto undef = declaration::Constant(undef_label.id(), expression::Ctor(ctor::Enum(undef_label)));
    nlabels.emplace_back(std::move(std::move(undef)));

    return nlabels;
}

std::vector<std::reference_wrapper<const type::enum_::Label>> type::Enum::labels() const {
    std::vector<std::reference_wrapper<const enum_::Label>> labels;

    for ( const auto& c : children() ) {
        const auto& label =
            c.as<declaration::Constant>().value().as<expression::Ctor>().ctor().as<ctor::Enum>().value();
        labels.emplace_back(label);
    }

    return labels;
}

std::vector<std::reference_wrapper<const type::enum_::Label>> type::Enum::uniqueLabels() const {
    auto pred_gt = [](const enum_::Label& e1, const enum_::Label& e2) { return e1.value() > e2.value(); };
    auto pred_eq = [](const enum_::Label& e1, const enum_::Label& e2) { return e1.value() == e2.value(); };

    auto in = labels();
    std::vector<std::reference_wrapper<const enum_::Label>> out;
    std::copy(in.begin(), in.end(), std::back_inserter(out));
    std::sort(out.begin(), out.end(), pred_gt);
    out.erase(std::unique(out.begin(), out.end(), pred_eq), out.end());
    return out;
}


void type::Enum::initLabelTypes(Node* n) {
    auto& etype = n->as<type::Enum>();

    std::vector<Node> nlabels;

    for ( const auto& l : etype.labels() ) {
        auto nlabel = enum_::Label(l.get(), NodeRef(*n));
        Declaration d = declaration::Constant(nlabel.id(), expression::Ctor(ctor::Enum(nlabel)));
        nlabels.emplace_back(std::move(d));
    }

    n->children() = std::move(nlabels);

    etype._initialized = true;
}
