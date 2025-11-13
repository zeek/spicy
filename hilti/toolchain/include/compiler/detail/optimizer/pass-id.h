// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <hilti/base/util.h>

namespace hilti::detail::optimizer {

/**
 * Declares a unique ID for each optimizer pass, also defining the order in
 * which passes run during processing. The order is defined by the integer
 * value of these enum tags, with passes having lower ID values executing
 * first. New passes should be inserted at the appropriate point.
 */
enum PassID {
    FeatureRequirements,
    DeadCodeStatic,
    Peephole,
    FlattenBlocks,
    DeadCodeCFG,
    ConstantPropagation,
    RemoveUnusedParameters,
};

namespace detail {
constexpr util::enum_::Value<PassID> PassIDs[] = {
    {.value = PassID::FeatureRequirements, .name = "feature-requirements"},
    {.value = PassID::DeadCodeStatic, .name = "dead-code-static"},
    {.value = PassID::Peephole, .name = "peephole"},
    {.value = PassID::DeadCodeCFG, .name = "dead-code-cfg"},
    {.value = PassID::ConstantPropagation, .name = "constant-propagation"},
    {.value = PassID::RemoveUnusedParameters, .name = "remove-unused-parameters"},
    {.value = PassID::FlattenBlocks, .name = "flatten-blocks"},
};
}

constexpr auto to_string(PassID m) { return util::enum_::to_string(m, detail::PassIDs); }
} // namespace hilti::detail::optimizer
