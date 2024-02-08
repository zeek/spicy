// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <algorithm>
#include <exception>

#include <hilti/ast/ctors/enum.h>
#include <hilti/ast/declarations/constant.h>
#include <hilti/ast/expressions/ctor.h>
#include <hilti/ast/types/enum.h>

using namespace hilti;

type::enum_::Label::~Label() {}

void type::Enum::_setLabels(ASTContext* ctx, enum_::Labels labels) {
    auto max = std::max_element(labels.begin(), labels.end(),
                                [](const auto& l1, const auto& l2) { return l1->value() < l2->value(); });
    auto next_value = (max != labels.end() ? (*max)->value() + 1 : 0);

    auto enum_type = QualifiedType::createExternal(ctx, as<type::Enum>(), Constness::Mutable);

    for ( auto&& l : labels ) {
        if ( util::tolower(l->id()) == "undef" )
            throw std::out_of_range("reserved enum label 'Undef' cannot be redefined");

        if ( l->value() < 0 )
            l->setValue(next_value++);

        l->setEnumType(ctx, enum_type);

        auto d = declaration::Constant::create(ctx, l->id(), expression::Ctor::create(ctx, ctor::Enum::create(ctx, l)));
        addChild(ctx, std::move(d));
    }

    auto undef_label = type::enum_::Label::create(ctx, ID("Undef"), -1, meta())->as<type::enum_::Label>();
    undef_label->setEnumType(ctx, enum_type);

    auto undef_decl =
        declaration::Constant::create(ctx, undef_label->id(),
                                      expression::Ctor::create(ctx, ctor::Enum::create(ctx, undef_label)));

    addChild(ctx, std::move(undef_decl));
}

type::enum_::Labels type::Enum::labels() const {
    enum_::Labels labels;

    for ( auto d : labelDeclarations() )
        labels.emplace_back(
            d->as<declaration::Constant>()->value()->as<expression::Ctor>()->ctor()->as<ctor::Enum>()->value());

    return labels;
}

type::enum_::Labels type::Enum::uniqueLabels() const {
    auto pred_gt = [](const auto& e1, const auto& e2) { return e1->value() > e2->value(); };
    auto pred_eq = [](const auto& e1, const auto& e2) { return e1->value() == e2->value(); };

    auto in = labels();
    enum_::Labels out;
    std::copy(in.begin(), in.end(), std::back_inserter(out));
    std::sort(out.begin(), out.end(), pred_gt);
    out.erase(std::unique(out.begin(), out.end(), pred_eq), out.end());
    return out;
}
