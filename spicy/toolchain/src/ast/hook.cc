// Copyright (c) 2020-2023 by the Zeek Project. See LICENSE for details.

#include <spicy/ast/declarations/hook.h>
#include <spicy/ast/types/unit-items/field.h>
#include <spicy/ast/types/unit.h>

using namespace spicy;

declaration::Hook::~Hook() {}

node::Properties declaration::Hook::properties() const {
    auto p = node::Properties{{"engine", to_string(_engine)},
                              {"unit_type", to_string(_unit_type_index)},
                              {"unit_field", to_string(_unit_field_index)}};
    return Declaration::properties() + p;
}
