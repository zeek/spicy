// Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

#pragma once

#include <utility>

#include <hilti/rt/fiber.h>
#include <hilti/rt/types/stream.h>

#include <spicy/rt/parsed-unit.h>
#include <spicy/rt/unit-context.h>

namespace spicy::rt {

template<typename T>
using UnitType = hilti::rt::ValueReference<T>;

template<typename T>
using UnitRef = hilti::rt::StrongReference<T>;

/** Defines the type of the generic version of units' public parsing functions. */
using Parse1Function = hilti::rt::Resumable (*)(hilti::rt::ValueReference<hilti::rt::Stream>&,
                                                const hilti::rt::Optional<hilti::rt::stream::View>&,
                                                const hilti::rt::Optional<UnitContext>& context);

/** Defines the type of the generic version of units' public parsing functions. */
template<typename T>
using Parse2Function = hilti::rt::Resumable (*)(UnitType<T>&, hilti::rt::ValueReference<hilti::rt::Stream>&,
                                                const hilti::rt::Optional<hilti::rt::stream::View>&,
                                                const hilti::rt::Optional<UnitContext>& context);

using Parse3Function = hilti::rt::Resumable (*)(hilti::rt::ValueReference<ParsedUnit>&,
                                                hilti::rt::ValueReference<hilti::rt::Stream>&,
                                                const hilti::rt::Optional<hilti::rt::stream::View>&,
                                                const hilti::rt::Optional<UnitContext>& context);

/**
 * Defines the type of the generic version of a units' public function to
 * instantiate a new `%context` instance.
 */
using ContextNewFunction = UnitContext (*)();

namespace sink::detail {
struct State;
} // namespace sink::detail

namespace detail {

/**
 *
 * Defines the type of a unit's parse function used when connected to a sink.
 * This is for internal use only.
 */
using ParseSinkFunction = std::pair<hilti::rt::StrongReferenceGeneric, spicy::rt::sink::detail::State*> (*)();
} // namespace detail

} // namespace spicy::rt
