// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <unordered_set>
#include <vector>

#include <spicy/compiler/detail/pir/ir/diagnostic.h>
#include <spicy/compiler/detail/pir/ir/package.h>

namespace spicy::detail::pir::analyses {

/**
 * Warns about unused fields of private units. A field counts as used if code addresses it or uses its parsed value
 * beyond storing it in the unit (for example, as `$$` in a hook). Passing the unit to foreign code, even inside a
 * tuple or container, counts as using all its fields. Public units are exempt because the host may read them.
 *
 * @param package a verified package
 * @return one `unused-field` warning per unused field, in package order
 */
std::vector<ir::Diagnostic> checkUnusedFields(const ir::Package& package);

/**
 * Whether each field is published on every path. A field is always present when every reachable `parser.finish` of
 * its unit's parser has published it. Otherwise it is conditional: some path, such as one through another case of a
 * switch, skips it. Presence depends only on publications, and optimization can change it, so query it after the last
 * pass that changes the package.
 */
struct FieldPresence {
    std::unordered_set<uint32_t> conditional; /**< by `DeclId` index */

    bool isConditional(ir::DeclId field) const { return conditional.contains(field.index); }
};

/** Computes the presence of every field in a verified package. */
FieldPresence fieldPresence(const ir::Package& package);

/**
 * Reports field reads that may run before parsing or assignment sets the field.
 * Checks each parser and its direct hook calls. Other calls are assumed to write any unit or field passed to them.
 * Checks all CFG paths without evaluating branch conditions. A read of a conditional field is not reported: it fails
 * at runtime if the field is unset, as the analysis cannot see the conditions that make it safe.
 *
 * @param package a verified package
 * @return one `field-read-before-parsed` error per such read, with a note at the field
 */
std::vector<ir::Diagnostic> checkFieldReads(const ir::Package& package);

} // namespace spicy::detail::pir::analyses
